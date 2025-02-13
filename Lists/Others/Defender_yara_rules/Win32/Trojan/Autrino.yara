rule Trojan_Win32_Autrino_A_2147706567_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autrino.A"
        threat_id = "2147706567"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Autrino"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "A_u_Tj_No123321Exe" ascii //weight: 1
        $x_1_2 = "csboybind.au" ascii //weight: 1
        $x_1_3 = "ThunderPlatform.exe" ascii //weight: 1
        $x_1_4 = "stormliv.exe" ascii //weight: 1
        $x_1_5 = "csboyDVD.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

