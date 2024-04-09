rule Mal_WIN_NjRAT_RAT_PE  {
        meta:
                description = "Use to detect NjRAT implant."
                author = "Phatcharadol Thangplub"
                date = "10-04-2024"

        strings:
                $s1 = "[ENTER]" fullword wide
                $s2 = "[kl]" fullword wide
                $s3 = "|'|'|" fullword wide

                /*
                        Process comparison in protect function.
                */
                $hex1 = { 08 6F [4] 6F [4] 72 [4] 16 28 [4] 16 FE 01 ( 60 | 08 ) }

                /*
                       Binding C2 on LateCall, and Send of client informations.
                */
                $hex2 = { 7E [4] 14 72 [4] 18 8D [4] 13 0? 11 0? 16 7E [4] 28 [4] 28 [4] 28 
                        [4] 28 [4] A2 00 11 0? 17 7E [4] 28 [4] 8C [4] A2 00 11 0? 14 14 14 
                        17 28 [4] 26 7E [4] 28 [4] 28 [4] 28 [4] 80 [4] 17 80 [4] 28 [4] 28 
                        [4] 26 }

        condition:
                uint16(0) == 0x5A4D and filesize >= 20KB and filesize <= 15MB and 
                (any of ($s*) and any of ($hex*)) 
}