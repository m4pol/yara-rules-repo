rule Mal_WIN_NanoCore_RAT_PE  {
        meta:
                description = "Use to detect NanoCore RAT implant."
                author = "Phatcharadol Thangplub"
                date = "10-04-2024"
        
        strings:
                $s1 = "ReadPacket []" fullword wide
                $s2 = "HandlePluginDetailsCommand" fullword wide
                $s3 = "PluginUninstalling" fullword wide
                $s4 = "InitializePlugin" fullword wide
                
                /*
                        Check available plugins for the update.
                */
                $hex1 = { 0D 38 [4] 02 09 9A 79 [4] 71 [4] 13 ?? 02 09 17 58 9A 74 [4] 13 
                        ?? 02 09 18 58 9A 79 [4] 71 [4] 0C 06 11 ?? 6F [4] 11 ?? 28 [4] 
                        13 ?? 11 ?? 2D ?? 07 11 ?? 8C [4] 6F [4] 2B ?? 11 ?? 7B [4] 08 
                        2E ?? 11 ?? 08 7D [4] 17 80 [4] 11 ?? 7B [4] 11 ?? 28 [4] 2D ?? 
                        07 11 ?? 8C [4] 6F [4] 17 80 [4] 72 [4] 11 ?? 8C [4] 28 [4] 28 }

                /*
                       Plugin uninstallation.
                */
                $hex2 = { 7E [4] 6F [4] 13 ?? 38 [4] 12 ?? 28 [4] 13 ?? 06 11 ?? 7B [4] 6F 
                        [4] 2D ?? 17 80 [4] 72 [4] 11 ?? 7B [4] 8C [4] 28 [4] 28 [4] 11 ?? 
                        7B [4] 2C ?? 17 80 [4] 11 ?? 7B [4] 2C }

        condition:
                uint16(0) == 0x5A4D and filesize >= 150KB and filesize <= 2MB and all of them
}
