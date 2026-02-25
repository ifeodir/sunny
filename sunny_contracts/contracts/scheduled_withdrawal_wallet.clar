;; Scheduled Withdrawal Wallet Smart Contract
;; Allows users to schedule future withdrawals with specific amounts and times

;; Error constants
(define-constant ERR-UNAUTHORIZED (err u100))
(define-constant ERR-INSUFFICIENT-BALANCE (err u101))
(define-constant ERR-INVALID-AMOUNT (err u102))
(define-constant ERR-INVALID-TIME (err u103))
(define-constant ERR-WITHDRAWAL-NOT-FOUND (err u104))
(define-constant ERR-WITHDRAWAL-NOT-READY (err u105))
(define-constant ERR-WITHDRAWAL-ALREADY-EXECUTED (err u106))

;; Data variables
(define-data-var next-withdrawal-id uint u1)

;; Data maps
;; User balances
(define-map user-balances principal uint)

;; Scheduled withdrawals
(define-map scheduled-withdrawals
  uint  ;; withdrawal-id
  {
    user: principal,
    amount: uint,
    scheduled-time: uint,
    executed: bool
  }
)

;; User's withdrawal IDs (for easy lookup)
(define-map user-withdrawals
  principal  ;; user
  (list 100 uint)  ;; list of withdrawal IDs
)

;; Public functions

;; Deposit STX into the wallet
(define-public (deposit (amount uint))
  (let ((current-balance (default-to u0 (map-get? user-balances tx-sender))))
    (begin
      (try! (stx-transfer? amount tx-sender (as-contract tx-sender)))
      (map-set user-balances tx-sender (+ current-balance amount))
      (ok amount)
    )
  )
)

;; Schedule a withdrawal
(define-public (schedule-withdrawal (amount uint) (scheduled-time uint))
  (let (
    (current-balance (default-to u0 (map-get? user-balances tx-sender)))
    (withdrawal-id (var-get next-withdrawal-id))
    (current-withdrawals (default-to (list) (map-get? user-withdrawals tx-sender)))
  )
    (asserts! (> amount u0) ERR-INVALID-AMOUNT)
    (asserts! (> scheduled-time block-height) ERR-INVALID-TIME)
    (asserts! (>= current-balance amount) ERR-INSUFFICIENT-BALANCE)
    
    ;; Deduct amount from user's available balance
    (map-set user-balances tx-sender (- current-balance amount))
    
    ;; Create scheduled withdrawal
    (map-set scheduled-withdrawals withdrawal-id {
      user: tx-sender,
      amount: amount,
      scheduled-time: scheduled-time,
      executed: false
    })
    
    ;; Add withdrawal ID to user's list
    (map-set user-withdrawals tx-sender (unwrap! (as-max-len? (append current-withdrawals withdrawal-id) u100) ERR-INVALID-AMOUNT))
    
    ;; Increment withdrawal ID counter
    (var-set next-withdrawal-id (+ withdrawal-id u1))
    
    (ok withdrawal-id)
  )
)

;; Execute a scheduled withdrawal
(define-public (execute-withdrawal (withdrawal-id uint))
  (let ((withdrawal-data (unwrap! (map-get? scheduled-withdrawals withdrawal-id) ERR-WITHDRAWAL-NOT-FOUND)))
    (asserts! (is-eq (get user withdrawal-data) tx-sender) ERR-UNAUTHORIZED)
    (asserts! (>= block-height (get scheduled-time withdrawal-data)) ERR-WITHDRAWAL-NOT-READY)
    (asserts! (is-eq (get executed withdrawal-data) false) ERR-WITHDRAWAL-ALREADY-EXECUTED)
    
    ;; Mark withdrawal as executed
    (map-set scheduled-withdrawals withdrawal-id (merge withdrawal-data { executed: true }))
    
    ;; Transfer STX to user
    (try! (as-contract (stx-transfer? (get amount withdrawal-data) tx-sender (get user withdrawal-data))))
    
    (ok (get amount withdrawal-data))
  )
)

;; Cancel a scheduled withdrawal (before execution)
(define-public (cancel-withdrawal (withdrawal-id uint))
  (let ((withdrawal-data (unwrap! (map-get? scheduled-withdrawals withdrawal-id) ERR-WITHDRAWAL-NOT-FOUND)))
    (asserts! (is-eq (get user withdrawal-data) tx-sender) ERR-UNAUTHORIZED)
    (asserts! (is-eq (get executed withdrawal-data) false) ERR-WITHDRAWAL-ALREADY-EXECUTED)
    
    ;; Return amount to user's available balance
    (let ((current-balance (default-to u0 (map-get? user-balances tx-sender))))
      (map-set user-balances tx-sender (+ current-balance (get amount withdrawal-data)))
    )
    
    ;; Mark withdrawal as executed (cancelled)
    (map-set scheduled-withdrawals withdrawal-id (merge withdrawal-data { executed: true }))
    
    (ok (get amount withdrawal-data))
  )
)

;; Emergency withdrawal (withdraw all available balance immediately)
(define-public (emergency-withdrawal)
  (let ((balance (default-to u0 (map-get? user-balances tx-sender))))
    (asserts! (> balance u0) ERR-INSUFFICIENT-BALANCE)
    
    ;; Reset user balance to 0
    (map-set user-balances tx-sender u0)
    
    ;; Transfer STX to user
    (try! (as-contract (stx-transfer? balance tx-sender tx-sender)))
    
    (ok balance)
  )
)

;; Read-only functions

;; Get user's available balance
(define-read-only (get-balance (user principal))
  (default-to u0 (map-get? user-balances user))
)

;; Get scheduled withdrawal details
(define-read-only (get-withdrawal (withdrawal-id uint))
  (map-get? scheduled-withdrawals withdrawal-id)
)

;; Get user's scheduled withdrawals
(define-read-only (get-user-withdrawals (user principal))
  (default-to (list) (map-get? user-withdrawals user))
)

;; Check if withdrawal is ready for execution
(define-read-only (is-withdrawal-ready (withdrawal-id uint))
  (match (map-get? scheduled-withdrawals withdrawal-id)
    withdrawal-data (and 
      (>= block-height (get scheduled-time withdrawal-data))
      (is-eq (get executed withdrawal-data) false)
    )
    false
  )
)

;; Get contract STX balance
(define-read-only (get-contract-balance)
  (stx-get-balance (as-contract tx-sender))
)

;; Get next withdrawal ID
(define-read-only (get-next-withdrawal-id)
  (var-get next-withdrawal-id)
)