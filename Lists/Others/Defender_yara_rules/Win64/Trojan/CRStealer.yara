rule Trojan_Win64_CRStealer_AAA_2147968033_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CRStealer.AAA!AMTB"
        threat_id = "2147968033"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CRStealer"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_15_1 = "\\cgaftermann.pdb" ascii //weight: 15
        $x_1_2 = "YOUR_DISCORD_WEBHOOK_URL_HERE" ascii //weight: 1
        $x_1_3 = "YOUR_FAKE_ERROR_MESSAGE_HERE" ascii //weight: 1
        $x_1_4 = "rememberName" ascii //weight: 1
        $x_1_5 = "rememberPass" ascii //weight: 1
        $x_1_6 = "??1_Lockit@std@@QEAA@XZ" ascii //weight: 1
        $x_1_7 = "??0_Lockit@std@@QEAA@H@Z" ascii //weight: 1
        $x_1_8 = "_lock_file" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

