rule Worm_Win32_Minerv_2147597882_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Minerv"
        threat_id = "2147597882"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Minerv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "55"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "C:\\WINDOWS\\system32\\Minerva.exe" ascii //weight: 10
        $x_10_2 = "\\Start Menu\\Programs\\Startup\\minerva.com" ascii //weight: 10
        $x_10_3 = "CreateRemoteThread" ascii //weight: 10
        $x_10_4 = "WriteProcessMemory" ascii //weight: 10
        $x_10_5 = "CreateToolhelp32Snapshot" ascii //weight: 10
        $x_1_6 = "\\Optical.exe" ascii //weight: 1
        $x_1_7 = "\\Hipotalamus.dll" ascii //weight: 1
        $x_1_8 = "\\New Game.exe" ascii //weight: 1
        $x_1_9 = "\\Minerva Game.exe" ascii //weight: 1
        $x_1_10 = "\\InjectCalc.exe" ascii //weight: 1
        $x_1_11 = "\\InjectMsconfig.exe" ascii //weight: 1
        $x_1_12 = "\\InjectRegedit.exe" ascii //weight: 1
        $x_1_13 = "\\InjectTaskman.exe" ascii //weight: 1
        $x_1_14 = "\\SongOfMemory.mid" ascii //weight: 1
        $x_1_15 = "\\EyesOnMe.mid" ascii //weight: 1
        $x_1_16 = "\\Loss_of_Me.mid" ascii //weight: 1
        $x_1_17 = "\\Victory.mid" ascii //weight: 1
        $x_1_18 = "LIBGCCW32-EH-2-SJLJ-GTHR-MINGW32" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

