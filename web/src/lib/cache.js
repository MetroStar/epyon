export const _cache = {
  _prefix: 'epyon_cache_',
  _version: null,
  _ttls: {
    '/api/stats': 60000,           // 1 minute
    '/api/applications': 60000,    // 1 minute
    '/api/scan-history': 120000,   // 2 minutes
    '/api/metrics': 300000,        // 5 minutes
    '/api/github-metrics': 600000, // 10 minutes
    'default': 30000,              // 30 seconds
  },
  
  // Metrics tracking
  _metrics: {
    hits: 0,
    misses: 0,
    writes: 0,
    version_mismatches: 0,
    ttl_expirations: 0,
    quota_errors: 0,
    staleness_measurements: [],  // {endpoint, age_ms, timestamp}
  },

  _getKey(url) {
    return this._prefix + url;
  },

  _getTTL(url) {
    for (const [pattern, ttl] of Object.entries(this._ttls)) {
      if (url.includes(pattern)) return ttl;
    }
    return this._ttls.default;
  },

  get(url) {
    try {
      const key = this._getKey(url);
      const item = localStorage.getItem(key);
      if (!item) {
        this._metrics.misses++;
        return null;
      }

      const { data, timestamp, version } = JSON.parse(item);
      const ttl = this._getTTL(url);
      const age = Date.now() - timestamp;

      // Check version mismatch (scan completion invalidates cache)
      if (this._version !== null && version !== this._version) {
        this._metrics.version_mismatches++;
        localStorage.removeItem(key);
        return null;
      }

      // Check TTL expiry
      if (age > ttl) {
        this._metrics.ttl_expirations++;
        localStorage.removeItem(key);
        return null;
      }

      // Cache hit — track staleness
      this._metrics.hits++;
      this._metrics.staleness_measurements.push({
        endpoint: url,
        age_ms: age,
        timestamp: new Date().toISOString(),
      });
      // Keep only last 100 measurements
      if (this._metrics.staleness_measurements.length > 100) {
        this._metrics.staleness_measurements.shift();
      }

      return data;
    } catch (_) {
      this._metrics.misses++;
      return null;
    }
  },

  set(url, data, serverVersion) {
    try {
      const key = this._getKey(url);
      const item = {
        data,
        timestamp: Date.now(),
        version: serverVersion !== undefined ? serverVersion : this._version,
      };
      localStorage.setItem(key, JSON.stringify(item));
      this._metrics.writes++;
      
      // Update our version tracker if server sent a new version
      if (serverVersion !== undefined && serverVersion !== this._version) {
        this._version = serverVersion;
      }
    } catch (error) {
      // localStorage quota exceeded or disabled
      this._metrics.quota_errors++;
      console.warn('Cache write failed:', error.message);
    }
  },

  clear() {
    try {
      const keys = Object.keys(localStorage);
      for (const key of keys) {
        if (key.startsWith(this._prefix)) {
          localStorage.removeItem(key);
        }
      }
    } catch (_) {}
  },

  invalidate() {
    this.clear();
    this._version = null;
  },
  
  getMetrics() {
    const total = this._metrics.hits + this._metrics.misses;
    const hitRate = total > 0 ? Math.round((this._metrics.hits / total) * 1000) / 10 : null;
    
    // Calculate average staleness
    const staleness = this._metrics.staleness_measurements;
    const avgStaleness = staleness.length > 0
      ? Math.round(staleness.reduce((sum, m) => sum + m.age_ms, 0) / staleness.length)
      : null;
    
    return {
      hits: this._metrics.hits,
      misses: this._metrics.misses,
      writes: this._metrics.writes,
      hit_rate_pct: hitRate,
      version_mismatches: this._metrics.version_mismatches,
      ttl_expirations: this._metrics.ttl_expirations,
      quota_errors: this._metrics.quota_errors,
      avg_staleness_ms: avgStaleness,
      current_version: this._version,
      recent_staleness: staleness.slice(-10),
    };
  },
};
