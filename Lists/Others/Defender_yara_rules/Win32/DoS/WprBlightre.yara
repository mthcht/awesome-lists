rule DoS_Win32_WprBlightre_B_2147894424_0
{
    meta:
        author = "defender2yara"
        detection_name = "DoS:Win32/WprBlightre.B!dha"
        threat_id = "2147894424"
        type = "DoS"
        platform = "Win32: Windows 32-bit platform"
        family = "WprBlightre"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[+] Round %d" ascii //weight: 1
        $x_1_2 = "lla/ teIuq/ swodahs   eteled nimdassv  c/ exe.dmc" ascii //weight: 1
        $x_1_3 = "seruliafllaerongi ycilopsutatstoob }tluafed{ tes / tidedcb c / exe.dmc" ascii //weight: 1
        $x_1_4 = "on delbaneyrevocer }tluafed{ tes/ tidedcb c/ exe.dmc" ascii //weight: 1
        $x_1_5 = "[+] CPU cores: %d, Threads: %d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule DoS_Win32_WprBlightre_C_2147911327_0
{
    meta:
        author = "defender2yara"
        detection_name = "DoS:Win32/WprBlightre.C!dha"
        threat_id = "2147911327"
        type = "DoS"
        platform = "Win32: Windows 32-bit platform"
        family = "WprBlightre"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[!] Waiting For  Queue" ascii //weight: 1
        $x_1_2 = "Deleting Disks..." ascii //weight: 1
        $x_1_3 = "DiskName: %s, Deleted: %d - %d" ascii //weight: 1
        $x_1_4 = "[+] Round %d" ascii //weight: 1
        $x_1_5 = "Israel" ascii //weight: 1
        $x_1_6 = "[+] OK, It wasn't ..." ascii //weight: 1
        $x_1_7 = "[+] CPU cores: %d, Threads: %d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

