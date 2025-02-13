rule Trojan_Win32_PSReflectiveLoader_A_2147730489_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PSReflectiveLoader.A"
        threat_id = "2147730489"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PSReflectiveLoader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershellrunner.powershellrunner" ascii //weight: 1
        $x_1_2 = "dfc4eebb-7384-4db5-9bad-257203029bd9" ascii //weight: 1
        $x_1_3 = "unmanagedpowershell-rdi.dll" ascii //weight: 1
        $x_1_4 = "runtimeclrhost::getcurrentappdomainid failed" ascii //weight: 1
        $x_1_5 = "invokeps" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

