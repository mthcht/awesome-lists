rule Trojan_Win32_Kexject_A_2147649569_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kexject.A"
        threat_id = "2147649569"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kexject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "started as injected kernel" ascii //weight: 1
        $x_1_2 = "StartKernelAsInjectedLibrary" ascii //weight: 1
        $x_1_3 = "CKernelInstaller::SetAutoRunValue" ascii //weight: 1
        $x_1_4 = "keProcInjectorMName" ascii //weight: 1
        $x_1_5 = "System\\Core2Inner" ascii //weight: 1
        $x_1_6 = "KeApplet" ascii //weight: 1
        $x_1_7 = "KernelFork" wide //weight: 1
        $x_1_8 = {54 45 4d 50 5c 6b 65 36 34 [0-16] 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

