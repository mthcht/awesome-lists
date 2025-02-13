rule Trojan_Win32_NSISInjector_DA_2147816357_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInjector.DA!MTB"
        threat_id = "2147816357"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInjector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "\\bruttotrkprocenten.exe" wide //weight: 3
        $x_3_2 = "\\*.log" wide //weight: 3
        $x_3_3 = "ArtDeco_brown_17.bmp" wide //weight: 3
        $x_3_4 = "face-laugh.png" wide //weight: 3
        $x_3_5 = "Autodesk Inc." wide //weight: 3
        $x_3_6 = "user32::CallWindowProcW(i R5 ,i 0,i 0, i 0, i 0)" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInjector_EK_2147825875_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInjector.EK!MTB"
        threat_id = "2147825875"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInjector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Phooey\\Slagsbroderen.lnk" wide //weight: 1
        $x_1_2 = "battery.png" wide //weight: 1
        $x_1_3 = "call-stop-symbolic.symbolic.png" wide //weight: 1
        $x_1_4 = "Biskoppelig" wide //weight: 1
        $x_1_5 = "folder-saved-search.png" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInjector_EM_2147826589_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInjector.EM!MTB"
        threat_id = "2147826589"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInjector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Interconnection" ascii //weight: 1
        $x_1_2 = "Sveddrivende" ascii //weight: 1
        $x_1_3 = "Gonyocele" ascii //weight: 1
        $x_1_4 = "Ranchless.exe" wide //weight: 1
        $x_1_5 = "GetShortPathNameA" ascii //weight: 1
        $x_1_6 = "CreateFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInjector_EM_2147826589_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInjector.EM!MTB"
        threat_id = "2147826589"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInjector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CHUDE\\Sulphocyanate.Kol" wide //weight: 1
        $x_1_2 = "Brown-Forman" wide //weight: 1
        $x_1_3 = "Pittston Brinks" wide //weight: 1
        $x_1_4 = "Xplode" wide //weight: 1
        $x_1_5 = "Nanosystems" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInjector_ER_2147834963_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInjector.ER!MTB"
        threat_id = "2147834963"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInjector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Tenselessness" ascii //weight: 1
        $x_1_2 = "Bankbestyrelser" ascii //weight: 1
        $x_1_3 = "mellemvgter" ascii //weight: 1
        $x_1_4 = "Buildup\\Skaldedes" wide //weight: 1
        $x_1_5 = "user-bookmarks-symbolic.svg" wide //weight: 1
        $x_1_6 = "emblem-important-symbolic.symbolic.png" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInjector_MFP_2147836006_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInjector.MFP!MTB"
        threat_id = "2147836006"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInjector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b2 bc ff 79 b2 bc ff 79 b2 bc ff 79 b2 bc ff}  //weight: 1, accuracy: High
        $x_1_2 = {79 b2 bc 0f 79}  //weight: 1, accuracy: High
        $x_1_3 = {b2 bc ff 78 b2 bc ff 78 b2 bc ff 78 b2 bc ff 78 b2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInjector_EC_2147842759_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInjector.EC!MTB"
        threat_id = "2147842759"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInjector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Skattedepartementet\\Anagogy.dll" ascii //weight: 1
        $x_1_2 = "\\Daitya.ini" ascii //weight: 1
        $x_1_3 = "\\Gldsfordring" ascii //weight: 1
        $x_1_4 = "AMD.Power.Processor.ppkg" ascii //weight: 1
        $x_1_5 = "\\Virtuosa\\Livor" ascii //weight: 1
        $x_1_6 = "PSReadline.psd1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInjector_RZ_2147897639_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInjector.RZ!MTB"
        threat_id = "2147897639"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInjector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c0 c8 03 32 82 a8 05 42 00 88 81 ?? ?? ?? ?? 8d 42 01 99 f7 fe 0f b6 81 ?? ?? ?? ?? c0 c8 03 32 82 a8 05 42 00 88 81 ?? ?? ?? ?? 8d 42 01 99}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

