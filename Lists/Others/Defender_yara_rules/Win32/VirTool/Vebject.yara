rule VirTool_Win32_Vebject_A_2147574771_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Vebject.A"
        threat_id = "2147574771"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Vebject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f5 40 00 00 00 f5 00 00 00 00 80 0c 00 2e d8 fc 40 04 24 ff 0a 0d 00 0c 00 3c 2d d8 fc f5 f8 00 00 00 6c 60 ff 80 0c 00 2e d8 fc 40 04 2c fe 0a 0d 00 0c 00 3c 2d d8 fc f5 44 00 00 00 71 a8 fd 0b 01 00 00 00 31 84 fc 04 ec fd 04 a8 fd 04 8c fc 1f 0e 00 04 8c fc f5 00 00 00 00 f5 00 00 00 00 f5 04 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 00 f4 00 e7 f5 00 00 00 00 f5 00 00 00 00 3e 84 fc 23 d4 fc 04 d0 fc 34 6c d0 fc f5 00 00 00 00 5e 0f 00 28 00 71 88 fc 3c 04 8c fc 04 a8 fd 20 0e 00 6c 88 fc f5 00 00 00 00 c7 32 06 00 d4 fc d0 fc 84 fc fe f6 8c fc 0e 00 1c b3 00 14 f5 02 00 01 00 71 dc fc 04 dc fc 6c f0 fd 5e 10 00 08 00 71 88}  //weight: 1, accuracy: High
        $x_1_3 = {fc 3c 6c 88 fc f5 00 00 00 00 c7 1c d9 00 1e 6b 02 f5 00 00 00 00 59 88 fc f5 04 00 00 00 04 74 ff 6c 80 fd f5 08 00 00 00 aa 6c ec fd 0a 11 00 14 00 3c 6c 74 ff f5 00 00 00 00 c7 1c 0a 01 1e 6b 02 f5 04 00 00 00 f5 00 30 00 00 6c 7c fe 6c 60 fe 6c ec fd 5e 12 00 14 00 71 88 fc 3c 6c 88 fc 71 6c ff}  //weight: 1, accuracy: High
        $x_1_4 = {6c 6c ff f5 00 00 00 00 c7 1c 66 01 6c 74 ff 6c ec fd 0a 13 00 08 00 3c f5 04 00 00 00 f5 00 30 00 00 6c 7c fe 6c 60 fe 6c ec fd 5e 12 00 14 00 71 88 fc 3c 6c 88 fc 71 6c ff 04 68 ff 6c 80 fe f5 00 00 00 00 80 0c 00 2e d8 fc 40 6c 6c ff 6c ec fd 0a 14 00 14 00 3c 2d d8 fc 6c 60 ff f5 f8 00 00 00 aa}  //weight: 1, accuracy: High
        $x_1_5 = {71 70 ff f5 00 00 00 00 04 64 ff 6b 32 fe f4 01 ad e7 fe 64 7c fc 2e 02 f5 28 00 00 00 6c 70 ff 6c 64 ff f5 28 00 00 00 b2 aa 80 0c 00 2e d8 fc 40 04 fc fd 04 54 fc 1f 15 00 04 54 fc 0a 0d 00 0c 00 3c 04 54 fc 04 fc fd 20 15 00 2d d8 fc 04 68 ff 6c 14 fe 6c 18 fe 80 0c 00 2e d8 fc 40 6c 6c ff 6c 10}  //weight: 1, accuracy: High
        $x_1_6 = {fe aa 6c ec fd 0a 14 00 14 00 3c 2d d8 fc 6c 28 fe 5e 16 00 04 00 71 88 fc 04 74 ff 6c 88 fc 6c 0c fe 6c 6c ff 6c 10 fe aa 6c ec fd 0a 17 00 14 00 3c 04 64 ff 66 7c fc a8 01 04 68 ff f5 04 00 00 00 04 6c ff 6c 80 fd f5 08 00 00 00 aa 6c ec fd 0a 14 00 14 00 3c 6c 6c ff 6c 54 fe aa 71 8c fd 04 dc fc}  //weight: 1, accuracy: High
        $x_1_7 = {6c f0 fd 0a 18 00 08 00 3c 6c f0 fd 0a 19 00 04 00 3c 14 6c f0 fd 0a 1a 00 04 00 3c 6c ec fd 0a 1a 00 04 00 3c 14}  //weight: 1, accuracy: High
        $x_1_8 = "mtpxnyeo7c0434sxdfZqC%P%DK<|!^ZS#d>}<C?B6Xc9WW~x8miG\\Ouenfuena[03,I(OW&G+.>~Y:HM&LJP9&]CTtHXD%*..h9" wide //weight: 1
        $x_1_9 = "-$bpQl}R&[?:aFE4s.FZTe,?!jx<5Io5eu5}|sR^K/]ZqC%P%DK<|!^ZS#d" wide //weight: 1
        $x_1_10 = ">}<C?B6Xc9WW~x8miG\\OO-|1Xa*^fjI(OW&G+.>~Y:HM&LJz:0PAQF9&]/]ZqC%P%DK<|!^ZS#d>}<C?B6Xc9WW~x8miG\\OO-|" wide //weight: 1
        $x_1_11 = "/BEG" wide //weight: 1
        $x_1_12 = "END\\" wide //weight: 1
        $x_1_13 = "/KEY" wide //weight: 1
        $x_1_14 = "KEY\\" wide //weight: 1
        $x_1_15 = "lNumberOfBitsToShift" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

