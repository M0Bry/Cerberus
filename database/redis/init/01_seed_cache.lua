-- Lua scripts for atomic operations
-- Atomic rate limit check
local function rate_limit_check(key, limit, window)
    local current = redis.call('INCR', key)
    if current == 1 then
        redis.call('EXPIRE', key, window)
    end
    if current > limit then
        return 0
    end
    return 1
end
