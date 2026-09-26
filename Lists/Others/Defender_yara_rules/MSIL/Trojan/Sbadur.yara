rule Trojan_MSIL_Sbadur_A_2147978934_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Sbadur.A!MTB"
        threat_id = "2147978934"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Sbadur"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {49 8d 0c 39 48 8b c6 48 83 e0 ?? 4a 33 0c 10 48 8b 6c 24 38 48 8b 5c 24 30 48 8b 74 24 40 48 83 c4}  //weight: 2, accuracy: Low
        $x_10_2 = "pub-86cc5b1d786144dcb24eecf62bbc7958.r2.dev" ascii //weight: 10
        $x_6_3 = "%sReader_en_install.exe" ascii //weight: 6
        $x_8_4 = "msiexec.exe /i \"%s\" REBOOT=ReallySuppress /qn" ascii //weight: 8
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

