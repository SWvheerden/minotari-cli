Feature: Fast Sync Scanning
  As a wallet user
  I want to quickly sync my wallet using fast sync
  So that I can see my balance faster than a normal full scan

  # =============================
  # Performance Comparisons
  # =============================
  Scenario: Fast sync without backfill is faster than normal sync when there are spent outputs
    Given I have a seed node MinerNode
    And I have a test database with a full signing wallet
    When I mine 20 blocks on MinerNode
    And I perform a normal full scan
    And I send 15 transactions
    And I mine 100 blocks on MinerNode
    And I reset the wallet database keeping account
    And I measure the time for a normal full scan
    And I reset the wallet database keeping account
    And I measure the time for a fast sync without backfill
    Then the fast sync should be faster than the normal scan

  Scenario: Fast sync without backfill completes in similar time to normal sync with no spent outputs
    Given I have a seed node MinerNode
    And I have a test database with an existing wallet
    When I mine 100 blocks on MinerNode
    And I measure the time for a normal full scan
    And I reset the wallet database
    And I measure the time for a fast sync without backfill
    Then the fast sync and normal scan should complete in similar time

  Scenario: Fast sync with backfill completes within reasonable time of normal sync
    Given I have a seed node MinerNode
    And I have a test database with a full signing wallet
    When I mine 10 blocks on MinerNode
    And I perform a normal full scan
    And I send 1 transactions
    And I mine 100 blocks on MinerNode
    And I reset the wallet database keeping account
    And I measure the time for a normal full scan
    And I reset the wallet database keeping account
    And I measure the time for a fast sync with backfill
    Then I print the fast sync benchmark results

  # =============================
  # Balance Correctness - No Transactions
  # =============================


  Scenario: Fast sync without backfill shows correct balance with no transactions
    Given I have a seed node MinerNode
    And I have a test database with an existing wallet
    When I mine 20 blocks on MinerNode to a different address
    And I perform a fast sync without backfill
    Then the fast sync should complete successfully
    And the fast sync balance should be zero

  Scenario: Fast sync with backfill shows correct balance with no transactions
    Given I have a seed node MinerNode
    And I have a test database with an existing wallet
    When I mine 20 blocks on MinerNode to a different address
    And I perform a fast sync without backfill
    And I perform a backfill scan
    Then the fast sync should complete successfully
    And the fast sync balance should be zero

  # =============================
  # Balance Correctness - With Transactions
  # =============================

  Scenario: Fast sync without backfill shows correct balance with transactions
    Given I have a seed node MinerNode
    And I have a test database with a full signing wallet
    When I mine 10 blocks on MinerNode
    And I perform a normal full scan
    And I send 1 transactions
    And I mine 10 blocks on MinerNode
    And I reset the wallet database keeping account
    And I perform a fast sync without backfill
    Then the fast sync should complete successfully
    And the fast sync balance should be at least 1 microTari

  Scenario: Fast sync with backfill shows correct balance with transactions
    Given I have a seed node MinerNode
    And I have a test database with a full signing wallet
    When I mine 10 blocks on MinerNode
    And I perform a normal full scan
    And I send 1 transactions
    And I mine 10 blocks on MinerNode
    And I reset the wallet database keeping account
    And I perform a fast sync without backfill
    And I perform a backfill scan
    Then the fast sync should complete successfully
    And the fast sync balance should be at least 1 microTari
