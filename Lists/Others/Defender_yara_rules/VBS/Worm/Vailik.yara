rule Worm_VBS_Vailik_A_2147692622_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:VBS/Vailik.A"
        threat_id = "2147692622"
        type = "Worm"
        platform = "VBS: Visual Basic scripts"
        family = "Vailik"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 00 53 00 65 00 6c 00 6c 00 4f 00 62 00 6a 00 2e 00 52 00 75 00 6e 00 20 00 22 00 77 00 73 00 63 00 72 00 69 00 70 00 74 00 2e 00 65 00 78 00 65 00 20 00 2f 00 2f 00 42 00 20 00 22 00 20 00 26 00 20 00 43 00 68 00 72 00 28 00 [0-8] 29 00 20 00 26 00 20 00 73 00 41 00 70 00 70 00 44 00 61 00 74 00 61 00 20 00 26 00 20 00 73 00 4e 00 61 00 6d 00 65 00 20 00 26 00 20 00 43 00 68 00 72 00 28 00 [0-8] 29 00 2c 00 20 00 30 00 2c 00 20 00 54 00 72 00 75 00 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = "Sub sUpdate(sURL)" wide //weight: 1
        $x_1_3 = "Sub sSpreadUSB()" wide //weight: 1
        $x_1_4 = "set lnkobj = sSellObj.createshortcut (drive.path & \"\\\"  & filename (0) & \".lnk\")" wide //weight: 1
        $x_1_5 = "Dim sBotData, sResponse, sCommand" wide //weight: 1
        $x_1_6 = "sBotData = HEXEncode(sXOR(sGetID & \"::\" & sGetOS & \"::\" & sGetUserPC & \"::\" & sGetRAM & \"::\" & sGetAV & \"::\" & IsUsb" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

