rule Trojan_Win32_Bravicae_A_2147679677_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bravicae.A"
        threat_id = "2147679677"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bravicae"
        severity = "6"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "7A38130D-BEB7-4d60-BE7A-4C4AB6A85CD1}" ascii //weight: 1
        $x_1_2 = "382338A5-0427-0410-92EC-745AD4E157CA}" ascii //weight: 1
        $x_1_3 = {00 56 43 42 61 72 2e 44 4c 4c 00}  //weight: 1, accuracy: High
        $x_1_4 = "44DD77;scrollbar-darkshadow-color:#117744;scrollbar-shadow-color:#447711;scrollbar-3dlight-color:#114477;}" ascii //weight: 1
        $x_1_5 = "mailto:bar@souhuu.com" ascii //weight: 1
        $x_1_6 = "bar.souhuu.com/welcome.asp?id=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

