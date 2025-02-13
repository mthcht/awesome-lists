rule SoftwareBundler_Win32_Stallmonitz_225956_0
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/Stallmonitz"
        threat_id = "225956"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "Stallmonitz"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "www.cooctdlfast.com/download.php?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule SoftwareBundler_Win32_Stallmonitz_225956_1
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/Stallmonitz"
        threat_id = "225956"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "Stallmonitz"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "{tmp}\\Install.exe" ascii //weight: 1
        $x_1_2 = "http://www.ntdlzone.com/download.php?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule SoftwareBundler_Win32_Stallmonitz_225956_2
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/Stallmonitz"
        threat_id = "225956"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "Stallmonitz"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\CBStub-Traction1.exe" ascii //weight: 1
        $x_1_2 = "/CBURL=http://www.coapr13south.com/download.php?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule SoftwareBundler_Win32_Stallmonitz_225956_3
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/Stallmonitz"
        threat_id = "225956"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "Stallmonitz"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "run data\\mtr.exe" ascii //weight: 1
        $x_1_2 = "runwait data\\bgb.exe /CBURL=http://www.cooctdlfast.com/download.php?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule SoftwareBundler_Win32_Stallmonitz_225956_4
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/Stallmonitz"
        threat_id = "225956"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "Stallmonitz"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "{app}\\CBStub.exe" ascii //weight: 10
        $x_1_2 = "/CBURL=http://www.mickyfastdl.com/download.php?" ascii //weight: 1
        $x_1_3 = "/CBURL=http://www.cojulyfastdl.com/download.php?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule SoftwareBundler_Win32_Stallmonitz_225956_5
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/Stallmonitz"
        threat_id = "225956"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "Stallmonitz"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "{tmp}\\stub" ascii //weight: 10
        $x_10_2 = "%s%d_install.exe" ascii //weight: 10
        $x_1_3 = "http://www.cooct13hen.com/download.php?" ascii //weight: 1
        $x_1_4 = "http://www.cosept13jetty.com/download.php?" ascii //weight: 1
        $x_1_5 = "http://www.cosept14water.com/download.php?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

