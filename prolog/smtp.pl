/*  Author:        Jan Wielemaker
    E-mail:        J.Wielemaker@cs.vu.nl
    WWW:           http://www.swi-prolog.org
    Copyright (C): 2010-2015, University of Amsterdam,
			      VU University Amsterdam

    This program is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

    As a special exception, if you link this library with other files,
    compiled with a Free Software compiler, to produce an executable, this
    library does not by itself cause the resulting executable to be covered
    by the GNU General Public License. This exception does not however
    invalidate any other reasons why the executable file might be covered by
    the GNU General Public License.
*/

:- module(smtp,
	  [ smtp_send_mail/3		% +To, :Goal, +Options
	  ]).
:- use_module(library(socket)).
:- use_module(library(readutil)).
:- use_module(library(settings)).
:- use_module(library(option)).
:- use_module(library(lists)).
:- use_module(library(debug)).
:- use_module(library(dcg/basics)).

:- meta_predicate
	smtp_send_mail(+, 1, +).

/** <module> Send E-mail through SMTP

This module provides a  simple  means  to   send  E-mail  from  a Prolog
application.  Here is a simple example:

==
send_message(Out) :-
	format(Out, 'Hi Alice,\n\n', []),
	format(Out, 'Want to go out tonight?\n\n', []),
	format(Out, '\tCheers, Bob\n', []).


?- smtp_send_mail('alice@wonderland.com',
		  send_message,
		  [ subject('Tonight'),
		    from('bob@wonderland.com')
		  ]).

This library currently supports good old  SMTP, encrypted and authorized
ESMTP. Both SSL/TLS and STARTTLS  encryption is supported. Authorization
is supported using =PLAIN= and =LOGIN= methods.

Data is currently being sent using the =DATA= keyword.

@tbd	Support more advanced data transport extensions such as sending
	MIME messages.
==
*/

:- setting(host, atom, localhost,
	   'Name of the SMTP host for relaying the mail').
:- setting(port, integer, 0,
	   'Port on which the SMTP host listens (0: default)').
:- setting(security, oneof([none,ssl,tls,starttls]), none,
	   'Security system to use').
:- setting(from, atom, '',
	   'Default from-address').
:- setting(user, atom, '',
	   'Default user to authenticate').
:- setting(password, atom, '',
	   'Default password for smtp:user').
:- setting(auth_method, oneof([plain,login,default]), default,
	   'Default authorization to use').
:- setting(hostname, atom, '',
	   'Default hostname').

%%	smtp_send_mail(+To, :Goal, +Options)
%
%	Send mail using SMTP.  To is the e-mail address of the receiver.
%	Options:
%
%	  * smtp(+Host)
%           the ip address for smtp host, eg. swi-prolog.org
%	  * from(+FromAddress)
%           atomic identifies sender address (does not set From: header)
%	  * subject(+Subject)
%           atomic: text for 'Subject:' email header
%	  * auth(User-Password)
%           authedication credentials, as atoms
%	  * auth_method(+PlainOrLoginOrNone)
%           type of authentication. Default is =default=, alternatives
%	    are =plain= and =login=
%         * security(Security)
%           one of: none, ssl, tls, starttls
%	  * content_type(+ContentType)
%           sets Content-Type header
%         * mailed_by(By)
%	    add X-Mailer: SWI-Prolog <version>, pack(smtp) to header
%	    iff By == true
%         * header(Name(Val))
%	    add HName: Val to headers. HName is Name if Name's first
%	    letter is a capital, and it is Name after capitalising its
%	    first letter otherwise. For instance header(from('My name,
%	    me@server.org')) adds header "From: My name, my@server.org"
%	    and header('FOO'(bar)) adds "FOO: bar"
%
%	Defaults are provided by settings associated to this module.
%
%	Listens to debug(smtp) which  for   instance  reports failure to
%	connect, (computation fails as per non-debug execution).
%
%	@param To is an atom holding the target address
%	@param Goal is called as call(Goal, Stream) and must provide the
%	       body of the message.

smtp_send_mail(To, Goal, Options) :-
	setting(security, DefSecurity),
	setting(host, DefHost),
	setting(port, DefPort0),
	option(security(Security), Options, DefSecurity),
	default_port(Security, DefPort0, DefPort),
	option(smtp(Host), Options, DefHost),
	option(port(Port), Options, DefPort),
	hostname(HostName, Options),
	(   setting(auth_method, AuthMethod),
	    AuthMethod \== default
	->  Extra = [auth_method(AuthMethod)]
	;   Extra = []
	),
	merge_options([ security(Security),
			port(Port),
			host(Host),
			hostname(HostName)
		      | Extra
		      ], Options, Options1),
	debug( smtp, 'Starting smtp with options: ~w', [Options] ),
	setup_call_cleanup(
	    smtp_open(Host:Port, In, Out, Options1),
	    do_send_mail(In, Out, To, Goal, Options1),
	    smtp_close(In, Out)).

%%	hostname(-HostName, +Options) is det.
%
%	Get the hostname used to identify me.

hostname(HostName, Options) :-
	option(hostname(HostName), Options), !.
hostname(HostName, _) :-
	setting(hostname, HostName), HostName \== '', !.
hostname(HostName, _) :-
	gethostname(HostName).

default_port(_, DefPort, DefPort) :-
	DefPort > 0, !.
default_port(none,      _,  25).
default_port(ssl,       _, 465).
default_port(tls,       _, 465).
default_port(starttls,  _, 587).

smtp_open(Address, In, Out, Options) :-
	tcp_socket(Socket),
	tcp_connect(Socket, Address),
	tcp_open_socket(Socket, In0, Out0),
	(   option(security(Security), Options),
	    ssl_security(Security)
	->  Address = Host:Port,
	    ssl_context(client, SSL,
			[ host(Host),
			  port(Port),
			  cert_verify_hook(cert_verify),
			  close_parent(true)
			]),
	    ssl_negotiate(SSL, In0, Out0, In, Out)
	;   In = In0,
	    Out = Out0
	),
	!.
smtp_open(Address, _In, _Out, Options) :-
	debug( smtp, 'Failed to open connection at address: ~w, with options: ~w', [Address,Options] ),
	fail.

:- public
	cert_verify/5.

cert_verify(_SSL, _ProblemCert, _AllCerts, _FirstCert, _Error) :-
        format(user_error, 'Accepting certificate~n', []).

ssl_security(ssl).
ssl_security(tls).

smtp_close(In, Out) :-
	close(Out),
	close(In).


%%	do_send_mail(+In, +Out, +To, :Goal, +Options) is det.
%
%	Perform the greeting and possibly upgrade   to TLS. Then proceed
%	using do_send_mail_cont/5.
%
%	Note that HELO is the old   SMTP  greeting. Modern systems greet
%	using EHLO, telling the other side they   want to speak RFC 1870
%	rather than the old RFC 821.
%
%	@tbd	Fall back to RFC 821 if the server does not understand
%		EHLO.  Probably not needed anymore?

do_send_mail(In, Out, To, Goal, Options) :-
	read_ok(In, 220),
	option(hostname(Me), Options),
	sock_send(Out, 'EHLO ~w\r\n', [Me]),
	read_ok(In, 250, Lines),
	setup_call_cleanup(
	    starttls(In, Out, In1, Out1, Lines, Lines1, Options),
	    do_send_mail_cont(In1, Out1, To, Goal, Lines1, Options),
	    close_tls(In, Out, In1, Out1)).

close_tls(In, Out, In, Out) :- !.
close_tls(_, _, In, Out) :-
	close(Out),
	close(In).

do_send_mail_cont(In, Out, To, Goal, Lines, Options) :-
	(   option(from(From), Options)
	->  true
	;   setting(from, From),
	    From \== ''
	->  true
	;   existence_error(smtp_option, from)
	),
	auth(In, Out, From, Lines, Options),
	sock_send(Out, 'MAIL FROM:<~w>\r\n', [From]),
	read_ok(In, 250),
	sock_send(Out, 'RCPT TO:<~w>\r\n', [To]),
	read_ok(In, 250),
	sock_send(Out, 'DATA\r\n', []),
	read_ok(In, 354),
	format(Out, 'To: ~w\r\n', [To]),
	header_options(Options, Out),
	sock_send(Out, '\r\n', []),
	call(Goal, Out),
	sock_send(Out, '\r\n.\r\n', []),
	read_ok(In, 250), !.
do_send_mail_cont(_In, _Out, To, _Goal, _Lines, Options ) :-
	debug(smtp, 'Failed to sent email To: ~w, with options: ~w',
	      [To,Options]),
	fail.

%%	starttls(+In0, +Out0, -In, -Out, +LinesIn, -LinesOut, +Options)
%
%	@tbd	Verify starttls is in Lines.

starttls(In0, Out0, In, Out, _Lines, Lines, Options) :-
	option(security(starttls), Options), !,
	option(host(Host), Options),
	option(port(Port), Options),
	sock_send(Out0, 'STARTTLS\r\n', []),
	read_ok(In0, 220),
	ssl_context(client, SSL,
		    [ host(Host),
		      port(Port),
		      cert_verify_hook(cert_verify)
		    ]),
	ssl_negotiate(SSL, In0, Out0, In, Out),
	option(hostname(Me), Options),
	sock_send(Out, 'EHLO ~w\r\n', [Me]),
	read_ok(In, 250, Lines).
starttls(In, Out, In, Out, Lines, Lines, _).


%%	auth(+In, +Out, +From, +Lines, +Options)
%
%	Negotiate authentication with the server. Currently supports the
%	=plain= and =login=  authentication   methods.  Authorization is
%	sent if the option =auth= is given   or  the settings =user= and
%	=password= are not the empty atom ('').
%
%	@param	Lines is the result of read_ok/3 on the EHLO command,
%		which tells us which authorizations are supported.

auth(In, Out, From, Lines, Options) :-
	(   option(auth(Auth), Options)
	;   setting(user, User), User \== '',
	    setting(password, Password), Password \== '',
	    Auth = User-Password
	), !,
	auth_supported(Lines, Supported),
	debug( smtp, 'Authentications supported: ~w, with options: ~w', [Supported,Options] ),
	auth_p(In, Out, From, Auth, Supported, Options).
auth(_, _, _, _, _).

auth_p(In, Out, From, User-Password, Protocols, Options) :-
	memberchk(plain, Protocols),
	\+ option(auth_method(login), Options), !,
	atom_codes(From, FromCodes),
	atom_codes(User, UserCodes),
	atom_codes(Password, PwdCodes),
	append([FromCodes, [0], UserCodes, [0], PwdCodes], Plain),
	phrase(base64(Plain), Encoded),
	sock_send(Out, 'AUTH PLAIN ~s\r\n', [Encoded]),
	read_ok(In, 235).
auth_p(In, Out, _From, User-Password, Protocols, _Options) :-
	memberchk(login, Protocols), !,
	sock_send(Out, 'AUTH LOGIN\r\n', []),
	read_ok(In, 334),
	base64(User, User64),
	sock_send(Out, '~w\r\n', [User64]),
	read_ok(In, 334),
	base64(Password, Password64),
	sock_send(Out, '~w\r\n', [Password64]),
	read_ok(In, 235).
auth_p(_In, _Out, _From, _Auth, _Protocols, _Options) :-
	representation_error(smtp_auth).

%%	auth_supported(+Lines, -Supported)
%
%	True  when  Supported  is  a  list  of  supported  authorization
%	protocols.

auth_supported(Lines, Supported) :-
	member(Line, Lines),
	downcase_atom(Line, Lower),
	atom_codes(Lower, Codes),
	phrase(auth(Supported), Codes), !.

auth(Supported) -->
	"auth", white, whites, !,
	auth_list(Supported).

auth_list([H|T]) -->
	nonblanks(Protocol), {Protocol \== []}, !,
	whites,
	{ atom_codes(H, Protocol)
	},
	auth_list(T).
auth_list([]) -->
	whites.

%%	sock_send(+Stream, +Format, +Args) is det.
%
%	Send the output of format(Format, Args)  to Stream and flush the
%	stream.

sock_send(Stream, Fmt, Args) :-
	format(Stream, Fmt, Args),
	flush_output(Stream).

header_options([], _).
header_options([H|T], Out) :-
	header_option(H, Out),
	header_options(T, Out).

header(subject, 'Subject').
header(content_type, 'Content-Type').

header_option(H, Out) :-
	H =.. [Name, Value],
	header(Name, Label), !,
	format(Out, '~w: ~w\r\n', [Label, Value]).
header_option(mailed_by(true), Out) :-
	current_prolog_flag( version_data, swi(Maj,Min,Pat,_) ),
	atomic_list_concat( [Maj,Min,Pat], '.', Vers ),	!,
	format(Out, 'X-Mailer: SWI-Prolog ~a, pack(smtp)\r\n', [Vers]).
header_option(header(Hdr), Out) :-
	Hdr =.. [HdrName, Value],
	header_key_upcase(HdrName, HdrAtom), !,
	format(Out, '~w: ~w\r\n', [HdrAtom, Value]).
header_option(_, _).

header_key_upcase(Name, Atom) :-
	sub_atom( Name, 0, 1, _, FirstOfName),
	upcase_atom(FirstOfName, FirstOfAtom),
	FirstOfAtom \== FirstOfName, !,
	sub_atom(Name, 1, _, 0, Unchanged),
	atom_concat(FirstOfAtom, Unchanged, Atom).
header_key_upcase(Name, Name).


%%	read_ok(+Stream, ?Code) is semidet.
%%	read_ok(+Stream, ?Code, -Lines) is semidet.
%
%	True if the server replies  with   Code.  The  version read_ok/3
%	returns the server comment lines, one atom per line. The numeric
%	code has been stripped from the lines.

read_ok(Stream, Code) :-
	read_ok(Stream, Code, _Reply).

read_ok(Stream, Code, [Line|Rest]) :-
	read_line_to_codes(Stream, Codes),
	parse_line(Codes, Code, Line, Cont),
	(   Cont == true
	->  read_reply_cont(Stream, Code, Rest)
	;   Rest = []
	).

read_reply_cont(Stream, Code, [Line|Rest]) :-
	read_line_to_codes(Stream, Codes),
	parse_line(Codes, Code1, Line, Cont),
	assertion(Code == Code1),
	(   Cont == true
	->  read_reply_cont(Stream, Code, Rest)
	;   Rest = []
	).

parse_line(Codes, Code, Line, Cont) :-
	phrase(reply_line(Code,Line,Cont), Codes), !.
parse_line(Codes, _, _, _) :-
	atom_codes(Atom, Codes),
	throw(error(smtp_error(unexpected_reply(Atom)), _)).

reply_line(Code, Line, Cont) -->
	integer(Code),
	(   "-"
	->  {Cont = true}
	;   " "
	->  {Cont = false}
	),
	rest(LineCodes),
	{ atom_codes(Line, LineCodes) }.

rest(LineCodes, LineCodes, []).

