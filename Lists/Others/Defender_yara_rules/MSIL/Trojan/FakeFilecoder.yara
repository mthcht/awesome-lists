rule Trojan_MSIL_FakeFilecoder_AJB_2147832250_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FakeFilecoder.AJB!MTB"
        threat_id = "2147832250"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FakeFilecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {70 14 14 73 ?? ?? ?? 0a 80 01 00 00 04 7e 01 00 00 04 14 fe 06 04 00 00 06}  //weight: 2, accuracy: Low
        $x_1_2 = "RemoteProcessKill.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FakeFilecoder_NFA_2147894989_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FakeFilecoder.NFA!MTB"
        threat_id = "2147894989"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FakeFilecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TPF2.Properties.Resources.resources" ascii //weight: 1
        $x_1_2 = "TapPiF.Properties" ascii //weight: 1
        $x_1_3 = "YOU BECOME THE VICTIM OF TAF.G MALWARE!" ascii //weight: 1
        $x_1_4 = "Boring of Project for Bomb of Extracting Files" ascii //weight: 1
        $x_1_5 = "your some file has been encrypted!" ascii //weight: 1
        $x_1_6 = "How to Decrypt My Files?" ascii //weight: 1
        $x_1_7 = "@Please_Read_Me@.exe" ascii //weight: 1
        $x_1_8 = "ToBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

