rule Mal_LNX_Kaiten_Botnet_ELF {
        meta:
                description = "Use to detect Kaiten botnet, and there variants."
                author = "Phatcharadol Thangplub"
                date = "10-04-2024"

        strings:
                $s1 = "kaiten.c"
                $s2 = "USER %s localhost localhost :%s"
                $s3 = "JOIN %s :%s"
                $s4 = /NOTICE %s :(ENABLE|DISABLE)/
                $s5 = /<target> (<port>|<secs>)/

                /*
                        IRC Send function call for IRC bot registeration.
                */
                $hex1 = { 4? 8b [5] 4? 8b [2] ( 4? 8b 4? ?? 8b 4? ?? 4? 89 f0 b? | ?? ?? ?? 4? 8b 15 ?? ?? ?? ?? 8b 05 ?? ?? ?? ?? 4? 89 f0 b? ) [4] 89 c7 b8 00 00 00 00 e8 }
                $hex2 = { 0? 00 a0 e1 [2] 9f e5 0c 20 a0 e1 ( ?? ?? 9f e5 ?? ?? eb | 0e ?0 a0 e1 ?? ?? ?? eb ) } //ARM

                /*
                        IRC message sender in Send function.
                */
                $hex3 = { 4? 8b 8? [4] 4? 89 c6 b? [4] e8 [4] b? [4] e8 [4] 4? 89 c2 8b 8? [4] b? [4] 89 c7 e8 }
                $hex4 = { 03 20 a0 e1 [3] eb [2] 9f e5 [3] eb 00 30 a0 e1 ?? 0? 1? e5 [2] 9f e5 03 20 a0 e1 [3] eb } //ARM

        condition:
                uint32(0) == 0x464C457F and filesize <= 250KB and ((2 of ($s*)) and (($hex1 or $hex2) or ($hex3 or $hex4)))
}