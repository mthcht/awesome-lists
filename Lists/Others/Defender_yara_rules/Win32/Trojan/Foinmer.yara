rule Trojan_Win32_Foinmer_A_2147676007_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Foinmer.A"
        threat_id = "2147676007"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Foinmer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 61 73 6b 6b 69 6c 6c 20 2f 46 20 2f 49 4d 20 69 65 78 70 6c 6f 72 65 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_2 = "%s\\Mozilla\\Firefox\\%s\\extensions.rdf" ascii //weight: 1
        $x_1_3 = "var in_hosts = {'my.mail.ru' :" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Foinmer_B_2147676008_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Foinmer.B"
        threat_id = "2147676008"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Foinmer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "?template='+in_hosts[the_host]+'&from='+the_host" wide //weight: 1
        $x_1_2 = "builder\\ie\\Release\\BHOinCPP.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

