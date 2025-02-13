rule Trojan_Win32_Ninsfurm_A_2147642652_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ninsfurm.A"
        threat_id = "2147642652"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ninsfurm"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Microsoft\\safesurf.exe" wide //weight: 1
        $x_1_2 = "\\Microsoft\\SafeSurf ABUSE README.txt" wide //weight: 1
        $x_1_3 = "loocker" wide //weight: 1
        $x_1_4 = "Microsoft Smss Service Sequrity" wide //weight: 1
        $x_1_5 = "v_1" wide //weight: 1
        $x_1_6 = "surfhide" wide //weight: 1
        $x_1_7 = "/q:a /c:\"install /q /l" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

