rule Trojan_VBS_CoinMiner_BP_2147721999_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:VBS/CoinMiner.BP!bit"
        threat_id = "2147721999"
        type = "Trojan"
        platform = "VBS: Visual Basic scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 46 58 20 73 63 72 69 70 74 20 63 6f 6d 6d 61 6e 64 73 0d 0a 0d 0a 50 61 74 68 3d [0-16] 6d 69 6e 65 72 0d 0a 53 61 76 65 50 61 74 68 0d 0a 53 65 74 75 70 3d 22 [0-16] 6d 69 6e 65 72 5c [0-16] 2e 76 62 73 22 0d 0a 53 69 6c 65 6e 74 3d 31}  //weight: 1, accuracy: Low
        $x_1_2 = "reg add HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

