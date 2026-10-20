rule Trojan_Win64_DataStealer_GVN_2147964043_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DataStealer.GVN!MTB"
        threat_id = "2147964043"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DataStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_2 = "/bot" ascii //weight: 1
        $x_1_3 = "/sendDocument" ascii //weight: 1
        $x_1_4 = "\\Google\\Chrome\\User Data\\Default\\Login Data" ascii //weight: 1
        $x_1_5 = "\\chrome_data.tmp" ascii //weight: 1
        $x_1_6 = "\\Bitcoin\\wallet.dat" ascii //weight: 1
        $x_1_7 = "\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\nkbihfbeogaeaoehlefnkodbefgpgknn" ascii //weight: 1
        $x_1_8 = "vmtoolsd.exe" ascii //weight: 1
        $x_1_9 = "vmwaretray.exe" ascii //weight: 1
        $x_1_10 = "vboxtray.exe" ascii //weight: 1
        $x_1_11 = "xenservice.exe" ascii //weight: 1
        $x_1_12 = "wireshark.exe" ascii //weight: 1
        $x_1_13 = "procmon.exe" ascii //weight: 1
        $x_1_14 = "processhacker.exe" ascii //weight: 1
        $x_1_15 = "x64dbg.exe" ascii //weight: 1
        $x_1_16 = "ghidra.exe" ascii //weight: 1
        $x_1_17 = "YOUR_CHAT_ID_HERE" ascii //weight: 1
        $x_1_18 = "YOUR_BOT_TOKEN_HERE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DataStealer_A_2147980619_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DataStealer.A!AMTB"
        threat_id = "2147980619"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DataStealer"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Neww Data Stealer" ascii //weight: 3
        $x_3_2 = "stealer" ascii //weight: 3
        $x_1_3 = "Rust Stealer" ascii //weight: 1
        $x_1_4 = "passwords decrypted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

