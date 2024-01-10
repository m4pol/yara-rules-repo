rule Kaiten_Botnet_ELF {
        meta:
                description = "Use to detect Kaiten/Tsunami botnet."
                author = "Phatcharadol Thangplub"
                date = "19-08-2023"
                update = "10-01-2024"


        strings:
                $s1 = "JOIN %s :%s"
                $s2 = "WHO %s"
                $s3 = "PONG %s"
                $s4 = "NICK %s"
                $s5 = "JOIN %s :%s"
                $s6 = "MODE %s -xi"
                $s7 = "%s : USERID : UNIX : %s"
                $s8 = "USER %s localhost localhost :%s" nocase
                $s9 = "NOTICE %s" nocase
                $s10 = "chan" nocase
                $s11 = { 3c 74 61 72 67 65 74 3e 20 3c 70 6f 72 74 3e ?? ?? ?? } //Attack command arguments.
                $s12 = { 47 45 54 53 50 4f 4f 46 ?? } //Spoof function name.
                $s13 = { ?? ?? 49 56 4d 53 47 } //Part of an IRC Command.
                $s14 = { ?? 50 4d 41 } //PMA exploit method.

                $x1 = "tsunami" nocase
                $x2 = "killall" nocase
                $x3 = "flooders" nocase
                $x4 = "help" nocase
                $x5 = "dispass" nocase
                $x6 = "kaiten.c"
                $x7 = "changeservers"
                $x8 = { ?? 4b 49 4c 4c 5f 50 4f 52 54 ?? ?? ?? ?? ?? ?? } //Command Report 1.
                $x9 = { ?? ?? ?? 41 6c 72 65 61 64 79 ?? } //Command Report 2.

        condition:
                uint32(0) == 0x464C457F and filesize < 350KB and (
                        (($s4 or $s6) and $s1 and $s2 and $s3 and $s5) and
                        ($s7 or $s8 or $s9) and 4 of  ($s10, $s11, $s12, $s13, $s14) and any of ($x*)
                )
}