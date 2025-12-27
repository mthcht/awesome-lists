rule Ransom_Win64_HellCat_B_2147957840_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/HellCat.B"
        threat_id = "2147957840"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "HellCat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[*] Initializing ETW evasion..." ascii //weight: 1
        $x_1_2 = "[*] Deleting shadow copies..." ascii //weight: 1
        $x_1_3 = "Starting service/process killer for %d" ascii //weight: 1
        $x_1_4 = "[*] Scanning system roots..." ascii //weight: 1
        $x_1_5 = "Encrypted %s successfully." ascii //weight: 1
        $x_1_6 = "[Propagation] Completed. Infected %d targets" ascii //weight: 1
        $x_1_7 = "[*] Renaming encrypted files..." ascii //weight: 1
        $x_1_8 = "[*] Deploying ransom notes..." ascii //weight: 1
        $x_1_9 = "[*] Changing desktop wallpaper..." ascii //weight: 1
        $x_1_10 = "Initiating self-destruct sequence..." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

