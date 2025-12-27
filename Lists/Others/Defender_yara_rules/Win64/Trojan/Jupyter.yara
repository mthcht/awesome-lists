rule Trojan_Win64_Jupyter_ARA_2147957579_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Jupyter.ARA!MTB"
        threat_id = "2147957579"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Jupyter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_6_1 = "\\eset\\malware\\test\\obj\\Release\\net8.0\\win-x64\\test.pdb" ascii //weight: 6
        $x_6_2 = "://api.ipify.org" wide //weight: 6
        $x_1_3 = "hostname" wide //weight: 1
        $x_1_4 = "username" wide //weight: 1
        $x_1_5 = "os_version" wide //weight: 1
        $x_1_6 = "processor" wide //weight: 1
        $x_1_7 = "machine" wide //weight: 1
        $x_1_8 = "local_ip" wide //weight: 1
        $x_1_9 = "public_ip" wide //weight: 1
        $x_1_10 = "mac_address =" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_6_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

