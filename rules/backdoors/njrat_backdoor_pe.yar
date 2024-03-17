rule NjRAT_Backdoor_PE {
        meta:
                description = "Use to detect NjRAT implant."
                author = "Phatcharadol Thangplub"
                date = "17-03-2024"

        strings:
                $s1 = "GetKeyboardState"
                $s2 = "capGetDriverDescriptionA"
                $s4 = "[ENTER]" fullword wide
                $s5 = "[TAP]" fullword wide
                $s6 = "|'|'|" fullword wide

                /*
                        Pattern of compare the process to kill it later, in protect function.
                */
                $hex1 = { 08 6F [4] 6F [4] 72 [4] 16 28 [4] 16 FE 01 }

                /*
                        Pattern on delete Registry Value.
                */
                $hex2 = { 7E [4] 6F [4] 6F [4] 7E [4] 17 6F [4] 7E [4] 16 6F [4] 00 }

                /*
                        Execute shell commands.
                */
                $hex3 = { 72 [4] 7E [4] 6F [4] 72 [4] 28 [4] 16 16 15 28 [4] 26 }

        condition:
                uint16(0) == 0x5A4D and filesize >= 20KB and (any of ($s*) and any of ($hex*))
}