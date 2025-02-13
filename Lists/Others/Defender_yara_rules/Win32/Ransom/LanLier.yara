rule Ransom_Win32_LanLier_R_2147734902_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LanLier.R!MTB"
        threat_id = "2147734902"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LanLier"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "all your files have been encrypted" ascii //weight: 1
        $x_1_2 = "Before paying you send us up to 3 files for free decryption" ascii //weight: 1
        $x_1_3 = "Decryption of your files with the help of third parties may cause increased price" ascii //weight: 1
        $x_1_4 = "HOW TO RECOVER ENCRYPTED FILES.TXT" ascii //weight: 1
        $x_1_5 = "[BACKUPS][DRIVES][SHARES][EXTENSION]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

