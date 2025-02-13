rule Trojan_MSIL_Qhost_A_2147638309_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Qhost.A"
        threat_id = "2147638309"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Qhost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Windows\\System32\\drivers\\etc\\hosts" wide //weight: 1
        $x_1_2 = "195.242.161.235 vkontakte.ru" wide //weight: 1
        $x_1_3 = "127.0.0.1 google.com" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Qhost_ARA_2147911898_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Qhost.ARA!MTB"
        threat_id = "2147911898"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Qhost"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "{6e3e989d-10a4-4862-a08a-b026f7a15c20}" ascii //weight: 2
        $x_2_2 = "MyFile.Resources.resources" ascii //weight: 2
        $x_2_3 = "CopyPasswordToolStripMenuItem.Image" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

