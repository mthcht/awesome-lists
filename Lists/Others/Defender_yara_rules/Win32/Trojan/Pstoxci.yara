rule Trojan_Win32_Pstoxci_A_2147745455_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pstoxci.A!MSR"
        threat_id = "2147745455"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pstoxci"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CredentialForm ik.PowerShell CREDUI_INFO CREDUI_FLAGS CredUIReturnCodes UserPwd PS2EXEHostRawUI" ascii //weight: 1
        $x_1_2 = "get_KeyValue set_VirtualKeyCode get_KeyCode get_Shift get_Alt get_Control get_Chars set_Character set_KeyDown ControlKeyStates" ascii //weight: 1
        $x_1_3 = "Press a key?#000080?#808080?#008000?#008080?#800080?#800000?#808000?#C0C0C0?#00FF00?" ascii //weight: 1
        $x_1_4 = "?^-([^: ]+)[ :]?([^:]*)$?True?$TRUE?False?$FALSE?out-string?stream?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

