rule VirTool_WinNT_Musomar_A_2147606853_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Musomar.A"
        threat_id = "2147606853"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Musomar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 95 57 53 89 5d 30 e8 ?? ?? ff ff 03 d8 85 f6 74 85 eb 19 3b 5d 1c 75 09 c7 45 2c 06 00 00 80 eb 0b 6a 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

