rule PerlBot_Botnet_Perl_Script {
        meta:
                description = "Use to detect Perl based IRC botnet."
                author = "Phatcharadol Thangplub"
                date = "19-08-2023"
                update = "10-01-2024"

        strings:
                $perl_sig = { 23 21 2f 75 73 72 2f 62 69 6e 2f 70 65 72 6c ?? } //Header declared of Perl Script.

                $func1 = "sub getstore ($$)"
                $func2 = "sub _get"
                $func3 = "sub _trivial_http_get"
                $func4 = "sub conectar" nocase
                $func5 = "sub parse" nocase
                $func6 = "sub bfunc" nocase
                $func7 = "sub ircase" nocase
                $func8 = "sub shell" nocase
                $func9 = "sub msg" nocase
                $func10 = "sub ctcp" nocase
                $func11 = "sub modo" nocase
                $func12 = "sub fixaddr" nocase

                $s1 = "$buf =~ s/.+?\\015?\\012\\015?\\012//s;"
                $s2 = "sendraw(\"USER $ircname \".$IRC_socket->sockhost.\" $servidor_con :$realname\");"
                $s3 = "($case =~ /^flood\\s+(\\d+)\\s+(\\S+) (.*)/)"
                $s4 = "($funcarg =~ /^flood/)"
                $s5 = "($case =~ /^ctcpflood\\s+(\\d+)\\s+(\\S+) (.*)/)"
                $s6 = "($funcarg =~ /^ctcpflood (.*)/)"
                $s7 = "sendraw($IRC_cur_socket, \"PRIVMSG $printl :$linha\");"

                $x1 = "sub attacker" nocase
                $x2 = "$shell = \"cmd.exe\";"
                $x3 = "($^O eq \"MSWin32\")"
                $x4 = "my $shell = \"/bin/sh -i\";"
                $x5 = "sub tcpflooder" nocase

        condition:
                filesize < 250KB and $perl_sig and (
                        4 of ($func1, $func2, $func3, $func4, $func5, $func6, $func7) and
                        ($func8 or $func9 or $func10 or $func11 or $func12) and 4 of ($s*) and any of ($x*)
                )
}