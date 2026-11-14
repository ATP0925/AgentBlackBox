param(
    [Parameter(ValueFromRemainingArguments = $true)]
    $Params
)
python -m agentblackbox @Params
