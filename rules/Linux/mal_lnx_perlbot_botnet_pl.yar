rule Mal_LNX_PerlBot_Botnet_PL {
        meta:
                description = "Use to detect Perl based IRC botnet."
                author = "Phatcharadol Thangplub"
                date = "10-04-2024"

        strings:
                $perl_header = "#!/usr/bin/perl"

                $func1 = "sub getstore ($$)"
                $func2 = "sub _get"
                $func3 = "sub _trivial_http_get"
                $func4 = "sub conectar"
                $func5 = "sub parse"
                $func6 = "sub bfunc"
                $func7 = "sub ircase"
                $func8 = "sub shell"
                $func9 = "sub msg"
                $func10 = "sub ctcp"
                $func11 = "sub modo"
                $func12 = "sub fixaddr"

                $s1 = "$buf =~ s/.+?\\015?\\012\\015?\\012//s;"
                $s2 = "sendraw(\"USER $ircname \".$IRC_socket->sockhost.\" $servidor_con :$realname\");"
                $s3 = "($case =~ /^flood\\s+(\\d+)\\s+(\\S+) (.*)/)"
                $s4 = "($funcarg =~ /^flood/)"
                $s5 = "($case =~ /^ctcpflood\\s+(\\d+)\\s+(\\S+) (.*)/)"
                $s6 = "($funcarg =~ /^ctcpflood (.*)/)"
                $s7 = "sendraw($IRC_cur_socket, \"PRIVMSG $printl :$linha\");"

        condition:
                $perl_header and filesize > 30KB and filesize <= 40KB and (6 of ($func*) and 4 of ($s*))
}