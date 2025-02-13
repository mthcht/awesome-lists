rule Ransom_Win32_CoSpri_2147725534_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/CoSpri"
        threat_id = "2147725534"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "CoSpri"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "spritecoind.dat" ascii //weight: 1
        $x_1_2 = "spritecoind.exe" ascii //weight: 1
        $x_1_3 = "libgcj-13.dll" ascii //weight: 1
        $x_1_4 = "Software\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_BROWSER_EMULATION" ascii //weight: 1
        $x_1_5 = "%0a%20%76%61%72%20%61%64%64%72%20%3d%20%63%68%61%72%73%2e%6a%6f%69%6e%28%27%27%29%2e%72%65%70%6c%61%63%65%28%2f%5b%5e%41%2d%5a%61%2d%7a%30%2d%39%5d%2f%67%2c%20%27%27%29%2e%73%6c%69%63%65%28%30%2c%39%35%29%3b" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

