rule AsyncRAT_Backdoor_PE {
        meta:
                description = "Use to detect AsyncRAT implant."
                author = "Phatcharadol Thangplub"
                date = "17-03-2024"

        strings:
                $s1 = "Select * from AntivirusProduct" fullword wide
                $s2 = "/c schtasks /create /f /sc onlogon /rl highest /tn" fullword wide
                $s3 = "QW1zaVNjYW5CdWZmZXI=" fullword wide
                $s4 = "YW1zaS5kbGw=" fullword wide
                $s5 = "SbieDll.dll" fullword wide

                /*
                        Load amsi.dll, get AmsiScanBuffer process address and allocate it in the memory.
                */
                $hex1 = { 28 [4] 72 [4] 28 [4] 6F [4] 0A 12 ?? 28 [4] 28 [4] 72 [4] 28 [4] 6F [4] 0B 12 ?? 28 [4] 0C 7E [4] 08 02 8E 69 6A 28 [4] 1F [1] 12 ?? 6F [4] 26 02 16 08 02 8E 69 28 }

                /*
                        Pattern of the PatchA function.
                */
                $hex2 = { 72 [4] 0A 06 72 [4] 28 [4] 0A 72 [4] 0B 07 72 [4] 28 [4] 0B 28 [4] 39 [4] 06 28 [4] 28 [4] 2A 07 28 [4] 28 [4] 2A }

                /*
                        Pattern of overload AES Encrypt function.
                */
                $hex3 = { 02 28 [4] 03 6F [4] 28 [4] 28 [4] 2A }
                $hex4 = { 06 07 6F [4] 17 73 [4] 0C 06 07 6F [4] 16 07 6F [4] 8E 69 6F [4] 08 03 16 03 8E 69 6F [4] 08 6F [4] 02 7B [4] 73 [4] 0D 09 06 6F [4] 1F ?? 06 6F [4] 8E 69 1F ?? 59 6F [4] 13 ?? 06 16 6A 6F [4] 06 11 ?? 16 11 ?? 8E 69 6F }

                /*
                        Pattern of the PreventSleep function.
                */
                $hex5 = { 20 [4] 28 [4] 26 DD }

        condition:
                uint16(0) == 0x5A4D and filesize >= 40KB and filesize <= 5MB and 
                (2 of ($s*) and (($hex1 and $hex2) or ($hex3 and $hex4)) and $hex5) 
}
