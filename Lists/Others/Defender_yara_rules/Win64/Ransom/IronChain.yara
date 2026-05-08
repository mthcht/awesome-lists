rule Ransom_Win64_IronChain_LVG_2147968877_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/IronChain.LVG!MTB"
        threat_id = "2147968877"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "IronChain"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PYINSTALLER_SUPPRESS_SPLASH_SCREEN" ascii //weight: 1
        $x_1_2 = "_PYI_ARCHIVE_FILE" ascii //weight: 1
        $x_1_3 = "_PYI_PARENT_PROCESS_LEVEL" ascii //weight: 1
        $x_1_4 = "_PYI_SPLASH_IPC" ascii //weight: 1
        $x_1_5 = "pyi-python-flag" ascii //weight: 1
        $x_1_6 = "pyi-runtime-tmpdir" ascii //weight: 1
        $x_1_7 = "pyi-contents-directory" ascii //weight: 1
        $x_1_8 = "pyi-disable-windowed-traceback" ascii //weight: 1
        $x_1_9 = "PYINSTALLER_STRICT_UNPACK_MODE" ascii //weight: 1
        $x_1_10 = "_PYI_APPLICATION_HOME_DIR" ascii //weight: 1
        $x_1_11 = "Failed to load splash screen resources!" ascii //weight: 1
        $x_1_12 = "Failed to remove temporary directory: %" ascii //weight: 1
        $x_1_13 = "Could not side-load PyInstaller's PKG" ascii //weight: 1
        $x_1_14 = "Could not load PyInstaller's embedded PKG" ascii //weight: 1
        $x_1_15 = "IronChain" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

