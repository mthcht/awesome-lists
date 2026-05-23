rule Trojan_Win32_XmrigMiner_AMTB_2147969988_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/XmrigMiner!AMTB"
        threat_id = "2147969988"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "XmrigMiner"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dev_poolH9" ascii //weight: 1
        $x_1_2 = "pool_pasH3" ascii //weight: 1
        $x_1_3 = "md/cminer-core\\src\\evasion\\defender.rs" ascii //weight: 1
        $x_1_4 = "miner_core.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

