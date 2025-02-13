rule Trojan_Win32_Pyderwdx_2147796127_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pyderwdx!dha"
        threat_id = "2147796127"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pyderwdx"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c %ws" wide //weight: 1
        $x_1_2 = "if exist %%1 del %%1 else goto Exit" ascii //weight: 1
        $x_1_3 = "WriteFakerSvchost() end" ascii //weight: 1
        $x_1_4 = "PyInject a process: [%ws][%ld]" ascii //weight: 1
        $x_1_5 = "Mozilla/5.0 (Windows; U; MSIE 9.0; WIndows NT 9.0; en-US))" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

