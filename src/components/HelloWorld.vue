<template>
    <div class="hero">
        <div>
            <h1 class="display-3">Hello!</h1>
            <form class="search-box" action="/search">
                <input type="text" placeholder="Looking for monitor?">
                <button class="btn" type="submit">Search</button>
            </form>
        </div>
    </div>
</template>

<style lang="scss">
.hero {
    height: 100%;
    display: flex;
    align-items: center;
    justify-content: center;
    text-align: center;

    .search-box {
        width: 40vw;
        min-width: 300px;
        display: flex;
        padding: 10px;
        background-color: #f0f0f0;
        input{
            flex: 3;
            margin-right: 10px;
            padding: 5px;
        }
        button {
            flex: 1;
            background-color: #3c4247;
            color: #fff;
        }
    }
}
</style>