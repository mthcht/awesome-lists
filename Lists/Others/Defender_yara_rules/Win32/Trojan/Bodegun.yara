rule Trojan_Win32_Bodegun_EH_2147843311_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bodegun.EH!MTB"
        threat_id = "2147843311"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bodegun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bhv.encryption.encrypt_files" ascii //weight: 1
        $x_1_2 = "bhv.ransom.ransom_note" ascii //weight: 1
        $x_1_3 = "Unable to get SeDebugPrivileges, may be unable to clean up child processes" ascii //weight: 1
        $x_1_4 = "LockBit_Ransomware.hta" ascii //weight: 1
        $x_1_5 = "Restore-My-Files.txt" ascii //weight: 1
        $x_1_6 = ".lockbit" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bodegun_GNF_2147896390_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bodegun.GNF!MTB"
        threat_id = "2147896390"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bodegun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b d0 83 e2 07 8a 4c 15 f8 30 0c 06 8d 54 15 f8 80 c1 1d 40 88 0a 3b c7}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

