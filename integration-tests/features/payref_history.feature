Feature: Payref history fallback after reorg
  As a wallet user
  I want transaction lookups by an old payment reference to keep resolving
  So that receipts issued before a block reorg remain verifiable

  Scenario: Displayed transaction payref survives a real blockchain reorg
    Given I have a seed node NodeA
    And I have a test database with an existing wallet
    # Mine blocks on NodeA so the wallet receives coinbase outputs
    When I mine 5 blocks on NodeA
    And I perform a scan with max blocks "20"
    Then the scan should complete successfully
    # Start the daemon so we can query transactions via the HTTP API
    When I start the daemon on a free port
    # Capture a payref from the scanned displayed transactions via the daemon API
    Then the wallet should have displayed transactions with payrefs
    When I capture a payref from the displayed transactions
    # Create a competing longer chain that will trigger a reorg
    Given I have an isolated base node NodeB
    When I mine 10 blocks on NodeB with a different wallet
    # Reconnect NodeA to NodeB so it adopts the longer chain
    And I restart NodeA connected to NodeB
    And I wait for NodeA to sync to height 10
    # Scan the wallet; the reorg handler detects the chain fork and saves old payrefs to history
    And I perform a scan with max blocks "50"
    Then the scan should complete successfully
    # Verify the old payref still resolves via the already-running daemon
    When I request the displayed transactions by the captured payref via the API
    Then the API should return the displayed transaction via history fallback
    # An unrelated payref should return empty
    When I request the displayed transactions by payref "never_seen_payref_xyz" via the API
    Then the API should return an empty list for the displayed transactions
