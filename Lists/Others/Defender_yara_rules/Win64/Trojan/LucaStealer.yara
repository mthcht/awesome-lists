rule Trojan_Win64_LucaStealer_NC_2147899137_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LucaStealer.NC!MTB"
        threat_id = "2147899137"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LucaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f 84 a3 00 00 00 48 8d 55 e0 49 89 c1 49 89 d8 48 c7 44 24 38 ?? ?? ?? ?? 48 8d 0d dc 41 0d 00 48 89 54 24 ?? 48 8d 55 e8 48 89 4c 24 ?? 31 c9 48 89 54 24 28}  //weight: 5, accuracy: Low
        $x_1_2 = "://zdv.life/downloader.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LucaStealer_GPA_2147918623_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LucaStealer.GPA!MTB"
        threat_id = "2147918623"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LucaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\regex\\string.rs" ascii //weight: 1
        $x_1_2 = "\\defense\\anti_dbg.rs" ascii //weight: 1
        $x_1_3 = "\\defense\\anti_vm.rs" ascii //weight: 1
        $x_1_4 = "\\discord.rs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LucaStealer_AB_2147953617_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LucaStealer.AB!MTB"
        threat_id = "2147953617"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LucaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 83 c0 40 48 89 c1 48 81 e1 00 ff ff ff 0f b6 d0 48 09 ca 48 8d ?? ?? ?? 48 89 f1 e8}  //weight: 1, accuracy: Low
        $x_1_2 = "logscx\\creditcards" ascii //weight: 1
        $x_1_3 = "logscx\\Telegram" ascii //weight: 1
        $x_1_4 = "logscx\\sensfiles.zip" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

