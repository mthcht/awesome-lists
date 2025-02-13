rule BrowserModifier_Win32_TogiraCby_224352_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/TogiraCby"
        threat_id = "224352"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "TogiraCby"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SELECT seq FROM sqlite_sequence WHERE name='addon'" ascii //weight: 1
        $x_1_2 = "INSERT INTO addon VALUES('" ascii //weight: 1
        $x_1_3 = "','extension','','','','','','','','','" ascii //weight: 1
        $x_2_4 = "Preferences Manager protects your browser search settings to keep programs from changing them without your knowledge." wide //weight: 2
        $x_1_5 = "INSERT INTO meta (key,value)  VALUES (\"Default Search Provider ID\"," ascii //weight: 1
        $x_2_6 = "Global\\{SS_EXE_RUNNING_15B475F3-750C-4889-A091-41A9E28FC471}" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

