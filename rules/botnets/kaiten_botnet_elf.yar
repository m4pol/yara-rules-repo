rule Kaiten_Botnet_ELF {
        meta:
                description = "Use to detect Kaiten/Tsunami botnet."
                author = "Phatcharadol Thangplub"
                date = "19-08-2023"
                update = "28-02-2024"

        strings:
                $s1 = "JOIN %s :%s"
                $s2 = "WHO %s"
                $s3 = "PONG %s"
                $s4 = "NICK %s"
                $s5 = "MODE %s -xi"
                $s6 = "%s : USERID : UNIX : %s"
                $s7 = "USER %s localhost localhost :%s" nocase
                $s8 = "NOTICE %s" nocase
                $s9 = "chan" nocase
                $s10 = "<target> <port>" nocase
                $s11 = "GETSPOOF" nocase
                $s12 = { ?? ?? 49 56 4d 53 47 } //IRC Command artifact.
                $s13 = { ?? 50 4d 41 } //PMA exploit method.

                $variant1 = "tsunami" nocase
                $variant2 = "killall" nocase
                $variant3 = "flooders" nocase
                $variant4 = "help" nocase
                $variant5 = "dispass" nocase
                $variant6 = "kaiten.c"
                $variant7 = "changeservers"
                $variant8 = { ?? 4b 49 4c 4c 5f 50 4f 52 54 ?? ?? ?? ?? ?? ?? } //Server Command Report.

        condition:
                uint32(0) == 0x464C457F and filesize < 350KB and (
                        (($s4 or $s6) and $s1 and $s2 and $s3 and $s5) and
                        ($s7 or $s8 or $s9) and 4 of  ($s10, $s11, $s12, $s13) and any of ($variant*)
                )
}