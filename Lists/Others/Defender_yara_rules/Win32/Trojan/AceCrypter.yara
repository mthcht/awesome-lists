rule Trojan_Win32_AceCrypter_PA_2147978641_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AceCrypter.PA!MTB"
        threat_id = "2147978641"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AceCrypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Namesusahak baruyemowizewap kenac figimaxif" ascii //weight: 5
        $x_5_2 = "zovugajoduricepeyosofahiwenayomu" ascii //weight: 5
        $x_5_3 = "Repa civafu gicamadafuse cehila yitayinisumuteh" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

