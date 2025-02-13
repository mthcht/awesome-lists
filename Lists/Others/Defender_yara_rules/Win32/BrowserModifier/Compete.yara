rule BrowserModifier_Win32_Compete_223418_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Compete"
        threat_id = "223418"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Compete"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "operated by Compete, Inc." ascii //weight: 1
        $x_1_2 = "open http://consumerinput.com/privacy" ascii //weight: 1
        $x_1_3 = "$$\\wininit.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Compete_223418_1
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Compete"
        threat_id = "223418"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Compete"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "?$mf3@_NVCChromeActivationMethod@@PAKV?$CComPtr@UIUIAutomationElement@@@ATL" ascii //weight: 1
        $x_1_2 = "@VCActivationController@@@detail@" ascii //weight: 1
        $x_1_3 = "Consumer Input has been added to Chrome." wide //weight: 1
        $x_1_4 = "CI Chrome Install Notice" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

