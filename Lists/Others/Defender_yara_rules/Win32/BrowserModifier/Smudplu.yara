rule BrowserModifier_Win32_Smudplu_223812_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Smudplu"
        threat_id = "223812"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Smudplu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CLSID\\{BC80074F-05FC-42b4-96F8-B2BE8E1148C0}" wide //weight: 1
        $x_1_2 = "\\Speedbit.Watchman\\Bin\\SearchModule" ascii //weight: 1
        $x_1_3 = "SBIEBrowserHelperObject.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Smudplu_223812_1
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Smudplu"
        threat_id = "223812"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Smudplu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[Agent::Application::QueryData]" wide //weight: 1
        $x_1_2 = "[Agent::Application::SendData]" wide //weight: 1
        $x_1_3 = "[Agent::StartOptions::Parse]" wide //weight: 1
        $x_1_4 = {2f 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 3a 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Smudplu_223812_2
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Smudplu"
        threat_id = "223812"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Smudplu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 20 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 6c 00 6e 00 6b 00 00 00 2e 00 6c 00 6e 00 6b 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {5c 00 43 00 6c 00 61 00 73 00 73 00 65 00 73 00 5c 00 41 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 73 00 5c 00 69 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 2e 00 65 00 78 00 65 00 5c 00 73 00 68 00 65 00 6c 00 6c 00 5c 00 6f 00 70 00 65 00 6e 00 5c 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 00 00 65 00 78 00 65 00 22 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {5c 00 49 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 20 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 5c 00 51 00 75 00 69 00 63 00 6b 00 20 00 4c 00 61 00 75 00 6e 00 63 00 68 00 5c 00 00 00 53 00 68 00 65 00 6c 00 6c 00 5f 00 54 00 72 00 61 00 79 00 57 00 6e 00 64 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Smudplu_223812_3
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Smudplu"
        threat_id = "223812"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Smudplu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[DNSMonitor::CheckAdapter]" wide //weight: 1
        $x_1_2 = "[CatchedProcess::InjectData]" wide //weight: 1
        $x_1_3 = "[Application::InstallTimeBomb]" wide //weight: 1
        $x_1_4 = "[Explorer::BrowserSettings::EnsureSearchScope]" wide //weight: 1
        $x_1_5 = "[Explorer::BrowserSettings::EnsureSearchHook]" wide //weight: 1
        $x_1_6 = {53 00 42 00 49 00 6e 00 6a 00 65 00 63 00 74 00 69 00 6f 00 6e 00 45 00 76 00 65 00 6e 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = "Injection::Snapshot::Controller::IsExplorerInstalled" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule BrowserModifier_Win32_Smudplu_223812_4
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Smudplu"
        threat_id = "223812"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Smudplu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "C15C42BB-4FDE64B3813743d9ABDC88EA185BE014" ascii //weight: 2
        $x_1_2 = "[Injector::Application::Run]" wide //weight: 1
        $x_1_3 = "[Injector::LibraryInjector::InjectLibrary]" wide //weight: 1
        $x_1_4 = {2f 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 49 00 64 00 3a 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = "%s?prd=%s&aff=%s&ver=%s&rnd=%d&usid=%s&pixGuid=%s" wide //weight: 1
        $x_1_6 = "Chrome event: Injection confirmed!" wide //weight: 1
        $x_1_7 = "[Chrome::Protector::IsValidLibraryToLoadA]" wide //weight: 1
        $x_1_8 = "[Chrome::Protector::UpdateRestoreOnStartupProtection]" wide //weight: 1
        $x_1_9 = "[Protector::OnStartPageChangedA] Previous:" wide //weight: 1
        $x_1_10 = "[Explorer::Protector::UpdateStartPageProtectionStatus]" wide //weight: 1
        $x_1_11 = "SetEvent:SB_EXPLORER_EVENT_SEARCH_ENGINE" wide //weight: 1
        $x_1_12 = {2f 00 73 00 65 00 61 00 72 00 63 00 68 00 2e 00 61 00 73 00 70 00 78 00 3f 00 73 00 69 00 74 00 65 00 3d 00 73 00 68 00 64 00 65 00 66 00 61 00 75 00 6c 00 74 00 [0-2] 26 00 70 00 72 00 64 00 3d 00 73 00 6d 00 77 00 26 00 70 00 69 00 64 00 3d 00 73 00 26 00 73 00 68 00 72 00 3d 00 64 00 26 00 71 00 3d 00 7b 00 73 00 65 00 61 00 72 00 63 00 68 00 54 00 65 00 72 00 6d 00 73 00 7d 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

