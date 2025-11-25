;; Enhanced Storage with Reset Delay Smart Contract
;; Advanced storage management with cooldown logic, history tracking, and access controls

;; Constants
(define-constant ERR_UNAUTHORIZED (err u100))
(define-constant ERR_COOLDOWN_ACTIVE (err u101))
(define-constant ERR_INVALID_VALUE (err u102))
(define-constant ERR_VALUE_TOO_HIGH (err u103))
(define-constant ERR_PAUSED (err u104))
(define-constant ERR_ALREADY_AUTHORIZED (err u105))
(define-constant ERR_NOT_AUTHORIZED (err u106))
(define-constant ERR_INVALID_THRESHOLD (err u107))

;; Configuration Constants
(define-constant DEFAULT_COOLDOWN_BLOCKS u60) ;; ~10 minutes
(define-constant MAX_VALUE u1000000) ;; Maximum allowed stored value
(define-constant MAX_HISTORY_SIZE u100) ;; Maximum history entries to keep

;; Data Variables
(define-data-var stored-value uint u0)
(define-data-var last-reset-block uint u0)
(define-data-var contract-owner principal tx-sender)
(define-data-var cooldown-period uint DEFAULT_COOLDOWN_BLOCKS)
(define-data-var contract-paused bool false)
(define-data-var total-resets uint u0)
(define-data-var value-threshold uint u500000)
(define-data-var auto-reset-enabled bool false)

;; Maps for advanced features
(define-map authorized-users principal bool)
(define-map user-reset-counts principal uint)
(define-map value-history uint {value: uint, block-height: uint, author: principal, action: (string-ascii 20)})
(define-map user-permissions principal {can-set: bool, can-reset: bool, can-admin: bool})

;; Data variable for history tracking
(define-data-var history-index uint u0)

;; Private Functions

;; Check if cooldown period has passed
(define-private (is-cooldown-expired)
  (>= (- block-height (var-get last-reset-block)) (var-get cooldown-period))
)

;; Calculate remaining cooldown blocks
(define-private (get-remaining-cooldown)
  (let ((blocks-since-reset (- block-height (var-get last-reset-block))))
    (if (>= blocks-since-reset (var-get cooldown-period))
      u0
      (- (var-get cooldown-period) blocks-since-reset)
    )
  )
)

;; Check if user is authorized
(define-private (is-authorized-user (user principal))
  (or 
    (is-eq user (var-get contract-owner))
    (default-to false (map-get? authorized-users user))
  )
)

;; Check user permissions
(define-private (has-permission (user principal) (permission (string-ascii 10)))
  (let ((perms (default-to {can-set: false, can-reset: false, can-admin: false} 
                          (map-get? user-permissions user))))
    (if (is-eq permission "admin")
      (get can-admin perms)
      (if (is-eq permission "set")
        (get can-set perms)
        (if (is-eq permission "reset")
          (get can-reset perms)
          false
        )
      )
    )
  )
)

;; Add entry to value history
(define-private (add-to-history (value uint) (action (string-ascii 20)))
  (let ((current-index (var-get history-index)))
    (map-set value-history current-index 
      {
        value: value,
        block-height: block-height,
        author: tx-sender,
        action: action
      }
    )
    (var-set history-index (+ current-index u1))
  )
)

;; Increment user reset count
(define-private (increment-user-resets (user principal))
  (let ((current-count (default-to u0 (map-get? user-reset-counts user))))
    (map-set user-reset-counts user (+ current-count u1))
  )
)

;; Check if auto-reset should trigger
(define-private (should-auto-reset)
  (and 
    (var-get auto-reset-enabled)
    (>= (var-get stored-value) (var-get value-threshold))
    (is-cooldown-expired)
  )
)

;; Public Functions

;; Enhanced getter with auto-reset check
(define-public (get-stored-value)
  (begin
    (asserts! (not (var-get contract-paused)) ERR_PAUSED)
    
    ;; Check if auto-reset should trigger
    (if (should-auto-reset)
      (begin
        (var-set stored-value u0)
        (var-set last-reset-block block-height)
        (var-set total-resets (+ (var-get total-resets) u1))
        (add-to-history u0 "auto-reset")
        (ok u0)
      )
      (ok (var-get stored-value))
    )
  )
)

;; Enhanced setter with validation and permissions
(define-public (set-value (new-value uint))
  (begin
    (asserts! (not (var-get contract-paused)) ERR_PAUSED)
    (asserts! (or (is-authorized-user tx-sender) (has-permission tx-sender "set")) ERR_UNAUTHORIZED)
    (asserts! (<= new-value MAX_VALUE) ERR_VALUE_TOO_HIGH)
    
    (var-set stored-value new-value)
    (add-to-history new-value "set-value")
    (ok new-value)
  )
)

;; Increment stored value
(define-public (increment-value (amount uint))
  (let ((current-val (var-get stored-value))
        (new-val (+ current-val amount)))
    (asserts! (not (var-get contract-paused)) ERR_PAUSED)
    (asserts! (or (is-authorized-user tx-sender) (has-permission tx-sender "set")) ERR_UNAUTHORIZED)
    (asserts! (<= new-val MAX_VALUE) ERR_VALUE_TOO_HIGH)
    
    (var-set stored-value new-val)
    (add-to-history new-val "increment")
    (ok new-val)
  )
)

;; Decrement stored value
(define-public (decrement-value (amount uint))
  (let ((current-val (var-get stored-value)))
    (asserts! (not (var-get contract-paused)) ERR_PAUSED)
    (asserts! (or (is-authorized-user tx-sender) (has-permission tx-sender "set")) ERR_UNAUTHORIZED)
    (asserts! (>= current-val amount) ERR_INVALID_VALUE)
    
    (let ((new-val (- current-val amount)))
      (var-set stored-value new-val)
      (add-to-history new-val "decrement")
      (ok new-val)
    )
  )
)

;; Enhanced reset function
(define-public (reset-value)
  (begin
    (asserts! (not (var-get contract-paused)) ERR_PAUSED)
    (asserts! (or (is-authorized-user tx-sender) (has-permission tx-sender "reset")) ERR_UNAUTHORIZED)
    (asserts! (is-cooldown-expired) ERR_COOLDOWN_ACTIVE)
    
    (var-set stored-value u0)
    (var-set last-reset-block block-height)
    (var-set total-resets (+ (var-get total-resets) u1))
    (increment-user-resets tx-sender)
    (add-to-history u0 "reset")
    (ok u0)
  )
)

;; Reset to custom value
(define-public (reset-to-value (new-value uint))
  (begin
    (asserts! (not (var-get contract-paused)) ERR_PAUSED)
    (asserts! (or (is-authorized-user tx-sender) (has-permission tx-sender "reset")) ERR_UNAUTHORIZED)
    (asserts! (is-cooldown-expired) ERR_COOLDOWN_ACTIVE)
    (asserts! (<= new-value MAX_VALUE) ERR_VALUE_TOO_HIGH)
    
    (var-set stored-value new-value)
    (var-set last-reset-block block-height)
    (var-set total-resets (+ (var-get total-resets) u1))
    (increment-user-resets tx-sender)
    (add-to-history new-value "reset-to-value")
    (ok new-value)
  )
)

;; Batch operations
(define-public (batch-set-values (values (list 10 uint)))
  (begin
    (asserts! (not (var-get contract-paused)) ERR_PAUSED)
    (asserts! (or (is-authorized-user tx-sender) (has-permission tx-sender "set")) ERR_UNAUTHORIZED)
    
    (let ((final-value (fold + values u0)))
      (asserts! (<= final-value MAX_VALUE) ERR_VALUE_TOO_HIGH)
      (var-set stored-value final-value)
      (add-to-history final-value "batch-set")
      (ok final-value)
    )
  )
)

;; Read-only Functions

;; Enhanced cooldown status
(define-read-only (get-cooldown-status)
  {
    cooldown-active: (not (is-cooldown-expired)),
    remaining-blocks: (get-remaining-cooldown),
    cooldown-period: (var-get cooldown-period),
    last-reset-block: (var-get last-reset-block),
    current-block: block-height,
    auto-reset-enabled: (var-get auto-reset-enabled),
    value-threshold: (var-get value-threshold)
  }
)

;; Get comprehensive contract info
(define-read-only (get-contract-info)
  {
    stored-value: (var-get stored-value),
    contract-owner: (var-get contract-owner),
    contract-paused: (var-get contract-paused),
    total-resets: (var-get total-resets),
    max-value: MAX_VALUE,
    history-count: (var-get history-index)
  }
)

;; Get user statistics
(define-read-only (get-user-stats (user principal))
  {
    is-authorized: (is-authorized-user user),
    reset-count: (default-to u0 (map-get? user-reset-counts user)),
    permissions: (default-to {can-set: false, can-reset: false, can-admin: false} 
                            (map-get? user-permissions user))
  }
)

;; Get value history entry
(define-read-only (get-history-entry (index uint))
  (map-get? value-history index)
)

;; Get recent history
(define-read-only (get-recent-history (count uint))
  (let ((current-index (var-get history-index))
        (start-index (if (>= current-index count) (- current-index count) u0)))
    {
      total-entries: current-index,
      start-index: start-index,
      requested-count: count
    }
  )
)

;; Administrative Functions

;; Pause/unpause contract
(define-public (toggle-pause)
  (begin
    (asserts! (is-eq tx-sender (var-get contract-owner)) ERR_UNAUTHORIZED)
    (var-set contract-paused (not (var-get contract-paused)))
    (ok (var-get contract-paused))
  )
)

;; Update cooldown period
(define-public (set-cooldown-period (new-period uint))
  (begin
    (asserts! (is-eq tx-sender (var-get contract-owner)) ERR_UNAUTHORIZED)
    (asserts! (and (>= new-period u1) (<= new-period u1000)) ERR_INVALID_VALUE)
    (var-set cooldown-period new-period)
    (ok new-period)
  )
)

;; Configure auto-reset
(define-public (configure-auto-reset (enabled bool) (threshold uint))
  (begin
    (asserts! (is-eq tx-sender (var-get contract-owner)) ERR_UNAUTHORIZED)
    (asserts! (<= threshold MAX_VALUE) ERR_INVALID_THRESHOLD)
    (var-set auto-reset-enabled enabled)
    (var-set value-threshold threshold)
    (ok {enabled: enabled, threshold: threshold})
  )
)

;; User management
(define-public (authorize-user (user principal))
  (begin
    (asserts! (is-eq tx-sender (var-get contract-owner)) ERR_UNAUTHORIZED)
    (asserts! (not (default-to false (map-get? authorized-users user))) ERR_ALREADY_AUTHORIZED)
    (map-set authorized-users user true)
    (ok user)
  )
)

(define-public (revoke-user (user principal))
  (begin
    (asserts! (is-eq tx-sender (var-get contract-owner)) ERR_UNAUTHORIZED)
    (asserts! (default-to false (map-get? authorized-users user)) ERR_NOT_AUTHORIZED)
    (map-delete authorized-users user)
    (map-delete user-permissions user)
    (ok user)
  )
)

;; Set granular permissions
(define-public (set-user-permissions (user principal) (can-set bool) (can-reset bool) (can-admin bool))
  (begin
    (asserts! (is-eq tx-sender (var-get contract-owner)) ERR_UNAUTHORIZED)
    (map-set user-permissions user {can-set: can-set, can-reset: can-reset, can-admin: can-admin})
    (ok user)
  )
)

;; Transfer ownership
(define-public (transfer-ownership (new-owner principal))
  (begin
    (asserts! (is-eq tx-sender (var-get contract-owner)) ERR_UNAUTHORIZED)
    (var-set contract-owner new-owner)
    (add-to-history u0 "ownership-transfer")
    (ok new-owner)
  )
)

;; Emergency functions
(define-public (emergency-reset)
  (begin
    (asserts! (is-eq tx-sender (var-get contract-owner)) ERR_UNAUTHORIZED)
    (var-set stored-value u0)
    (var-set last-reset-block block-height)
    (var-set total-resets (+ (var-get total-resets) u1))
    (add-to-history u0 "emergency-reset")
    (ok u0)
  )
)

(define-public (emergency-pause)
  (begin
    (asserts! (is-eq tx-sender (var-get contract-owner)) ERR_UNAUTHORIZED)
    (var-set contract-paused true)
    (add-to-history (var-get stored-value) "emergency-pause")
    (ok true)
  )
)