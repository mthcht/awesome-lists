rule Trojan_Win32_PSWZbot_UR_2147812989_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PSWZbot.UR!MTB"
        threat_id = "2147812989"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PSWZbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wtng.exe" ascii //weight: 1
        $x_1_2 = "@drws4" ascii //weight: 1
        $x_1_3 = "pcsws.exe" ascii //weight: 1
        $x_1_4 = "HTTP/1.1" ascii //weight: 1
        $x_1_5 = "hNPVDHKbH\\N" ascii //weight: 1
        $x_1_6 = "Gzpcgp`v@\\no\\xnzHjq[Sndw{l|jTDchFZEXVE" ascii //weight: 1
        $x_1_7 = "micrsolv" ascii //weight: 1
        $x_1_8 = "bankman" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

