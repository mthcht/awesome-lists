rule Trojan_Win64_Truenixicide_ATR_2147972156_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Truenixicide.ATR!MTB"
        threat_id = "2147972156"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Truenixicide"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vssadmin.exe delete shadows /all /quiet" ascii //weight: 1
        $x_1_2 = "bcdedit /set {default} recoveryenabled No" ascii //weight: 1
        $x_1_3 = "wbadmin DELETE SYSTEMSTATEBACKUP" ascii //weight: 1
        $x_1_4 = "Temp\\bonzi_setup.exe" ascii //weight: 1
        $x_1_5 = "www.bonzi.com" ascii //weight: 1
        $x_1_6 = "Global\\Truenixcide_Worm_Infection_Mutex" ascii //weight: 1
        $x_1_7 = "SYSTEM BREACH: TRUENIXCIDE.QUAD" ascii //weight: 1
        $x_1_8 = "NETWORK: Scanning local LAN for propagation" ascii //weight: 1
        $x_1_9 = "Shadow copies marked for deletion" ascii //weight: 1
        $x_1_10 = "Boot recovery disabled via bcdedit" ascii //weight: 1
        $x_1_11 = "External payload downloaded from remote server" ascii //weight: 1
        $x_1_12 = "Self-replication initialized on drives D-Z" ascii //weight: 1
        $x_1_13 = "PAYMENT REQUIRED: 0.1 BTC" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

